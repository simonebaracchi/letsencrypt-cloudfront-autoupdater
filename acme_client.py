"""Minimal ACME v2 client for HTTP-01 challenges."""

import base64
import hashlib
import json
import time

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def _b64url(data):
    """Base64url-encode bytes without padding."""
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_int(n):
    """Base64url-encode a positive integer."""
    byte_length = (n.bit_length() + 7) // 8
    return _b64url(n.to_bytes(byte_length, byteorder="big"))


class AcmeClient:
    """ACME v2 client supporting HTTP-01 domain validation."""

    POLL_INTERVAL = 2
    POLL_TIMEOUT = 180

    def __init__(self, directory_url, account_key):
        self.directory_url = directory_url
        self.account_key = account_key
        self._directory = None
        self._nonce = None
        self.account_url = None

    # ── directory & nonce ─────────────────────────────────────────────────

    def _get_directory(self):
        if self._directory is None:
            resp = requests.get(self.directory_url, timeout=30)
            resp.raise_for_status()
            self._directory = resp.json()
        return self._directory

    def _get_nonce(self):
        if self._nonce:
            nonce = self._nonce
            self._nonce = None
            return nonce
        directory = self._get_directory()
        resp = requests.head(directory["newNonce"], timeout=30)
        resp.raise_for_status()
        return resp.headers["Replay-Nonce"]

    # ── JWK / thumbprint ─────────────────────────────────────────────────

    def _jwk(self):
        pub_numbers = self.account_key.public_key().public_numbers()
        return {
            "e": _b64url_int(pub_numbers.e),
            "kty": "RSA",
            "n": _b64url_int(pub_numbers.n),
        }

    def _thumbprint(self):
        jwk = self._jwk()
        canonical = json.dumps(jwk, sort_keys=True, separators=(",", ":"))
        return _b64url(hashlib.sha256(canonical.encode()).digest())

    # ── signed requests ──────────────────────────────────────────────────

    def _signed_request(self, url, payload):
        """Send a JWS-signed POST to an ACME endpoint.

        payload=None sends a POST-as-GET (empty payload string).
        """
        protected = {
            "alg": "RS256",
            "nonce": self._get_nonce(),
            "url": url,
        }
        if self.account_url:
            protected["kid"] = self.account_url
        else:
            protected["jwk"] = self._jwk()

        protected_b64 = _b64url(json.dumps(protected))
        payload_b64 = "" if payload is None else _b64url(json.dumps(payload))

        signing_input = f"{protected_b64}.{payload_b64}".encode()
        signature = self.account_key.sign(
            signing_input,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )

        body = {
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": _b64url(signature),
        }
        resp = requests.post(
            url,
            json=body,
            headers={"Content-Type": "application/jose+json"},
            timeout=30,
        )
        self._nonce = resp.headers.get("Replay-Nonce")
        return resp

    # ── ACME operations ──────────────────────────────────────────────────

    def register(self, email):
        """Register a new account or retrieve an existing one (idempotent)."""
        directory = self._get_directory()
        payload = {
            "termsOfServiceAgreed": True,
            "contact": [f"mailto:{email}"],
        }
        resp = self._signed_request(directory["newAccount"], payload)
        if resp.status_code not in (200, 201):
            raise RuntimeError(
                f"Account registration failed: {resp.status_code} {resp.text}"
            )
        self.account_url = resp.headers["Location"]
        return resp.json()

    def new_order(self, domains):
        """Create a new certificate order."""
        directory = self._get_directory()
        payload = {
            "identifiers": [{"type": "dns", "value": d} for d in domains],
        }
        resp = self._signed_request(directory["newOrder"], payload)
        if resp.status_code not in (200, 201):
            raise RuntimeError(
                f"New order failed: {resp.status_code} {resp.text}")
        order = resp.json()
        order["url"] = resp.headers.get("Location", "")
        return order

    def get_authorization(self, auth_url):
        resp = self._signed_request(auth_url, None)
        resp.raise_for_status()
        return resp.json()

    def get_http01_challenge(self, authorization):
        for challenge in authorization["challenges"]:
            if challenge["type"] == "http-01":
                return challenge
        raise RuntimeError("No HTTP-01 challenge found in authorization")

    def key_authorization(self, token):
        """Compute key authorization: token.thumbprint"""
        return f"{token}.{self._thumbprint()}"

    def respond_to_challenge(self, challenge_url):
        """Tell the ACME server to verify the challenge."""
        resp = self._signed_request(challenge_url, {})
        if resp.status_code not in (200, 202):
            raise RuntimeError(
                f"Challenge response failed: {resp.status_code} {resp.text}"
            )
        return resp.json()

    def poll_until_valid(self, url, entity_type="authorization"):
        """Poll an authorization or order URL until status is 'valid'."""
        deadline = time.time() + self.POLL_TIMEOUT
        while time.time() < deadline:
            resp = self._signed_request(url, None)
            resp.raise_for_status()
            data = resp.json()
            status = data.get("status")
            if status == "valid":
                return data
            if status == "invalid":
                raise RuntimeError(
                    f"{entity_type} became invalid: {json.dumps(data, indent=2)}"
                )
            time.sleep(self.POLL_INTERVAL)
        raise RuntimeError(
            f"Timeout waiting for {entity_type} to become valid")

    def finalize_order(self, finalize_url, csr_der):
        """Finalize an order with the given DER-encoded CSR."""
        payload = {"csr": _b64url(csr_der)}
        resp = self._signed_request(finalize_url, payload)
        if resp.status_code not in (200, 202):
            raise RuntimeError(
                f"Finalize failed: {resp.status_code} {resp.text}")
        return resp.json()

    def download_certificate(self, cert_url):
        """Download the issued certificate chain (PEM)."""
        resp = self._signed_request(cert_url, None)
        resp.raise_for_status()
        return resp.text
