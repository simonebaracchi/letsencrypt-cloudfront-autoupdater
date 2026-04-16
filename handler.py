"""AWS Lambda handler for automated Let's Encrypt certificate renewal."""

import datetime
import logging
import os
import re

import boto3
import yaml
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from acme_client import AcmeClient

logger = logging.getLogger()
logger.setLevel(logging.INFO)

RENEWED = "renewed"
SKIPPED = "skipped"
FAILED = "failed"

RENEWAL_THRESHOLD_DAYS = 30


def load_config():
    config_path = os.path.join(os.path.dirname(__file__), "config.yaml")
    with open(config_path) as f:
        return yaml.safe_load(f)


def load_account_key():
    key_path = os.path.join(os.path.dirname(__file__), "account.key")
    with open(key_path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def get_distribution_info(cf_client, dist_id):
    """Get domains, S3 bucket, current cert ARN, config, and ETag."""
    resp = cf_client.get_distribution_config(Id=dist_id)
    config = resp["DistributionConfig"]
    etag = resp["ETag"]

    aliases = config.get("Aliases", {})
    domains = aliases.get("Items", []) if aliases.get(
        "Quantity", 0) > 0 else []

    s3_bucket = None
    for origin in config.get("Origins", {}).get("Items", []):
        domain_name = origin.get("DomainName", "")
        match = re.match(r"^(.+?)\.s3[.\-]", domain_name)
        if match:
            s3_bucket = match.group(1)
            break

    viewer_cert = config.get("ViewerCertificate", {})
    cert_arn = viewer_cert.get("ACMCertificateArn")

    return {
        "domains": domains,
        "s3_bucket": s3_bucket,
        "cert_arn": cert_arn,
        "config": config,
        "etag": etag,
    }


def needs_renewal(acm_client, cert_arn):
    if not cert_arn:
        return True
    try:
        resp = acm_client.describe_certificate(CertificateArn=cert_arn)
        not_after = resp["Certificate"]["NotAfter"]
        if not_after.tzinfo is None:
            not_after = not_after.replace(tzinfo=datetime.timezone.utc)
        remaining = not_after - datetime.datetime.now(datetime.timezone.utc)
        logger.info("Certificate %s expires in %d days",
                    cert_arn, remaining.days)
        return remaining.days < RENEWAL_THRESHOLD_DAYS
    except Exception as e:
        logger.warning("Could not check certificate %s: %s", cert_arn, e)
        return True


def upload_challenge(s3_client, bucket, token, content):
    key = f".well-known/acme-challenge/{token}"
    expires = datetime.datetime.now(
        datetime.timezone.utc) + datetime.timedelta(hours=1)
    s3_client.put_object(
        Bucket=bucket,
        Key=key,
        Body=content.encode(),
        ContentType="text/plain",
        Expires=expires,
    )
    logger.info("Uploaded challenge to s3://%s/%s", bucket, key)


def delete_challenge(s3_client, bucket, token):
    key = f".well-known/acme-challenge/{token}"
    s3_client.delete_object(Bucket=bucket, Key=key)
    logger.info("Deleted challenge s3://%s/%s", bucket, key)


def generate_csr(domains):
    """Generate a fresh private key and CSR for the given domains."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, domains[0]),
    ])
    san = x509.SubjectAlternativeName([x509.DNSName(d) for d in domains])

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .add_extension(san, critical=False)
        .sign(key, hashes.SHA256())
    )

    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    csr_der = csr.public_bytes(serialization.Encoding.DER)
    return key_pem, csr_der


def split_pem_chain(pem_text):
    """Split a PEM chain into the end-entity certificate and the CA chain."""
    certs = re.findall(
        r"(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)",
        pem_text,
        re.DOTALL,
    )
    if not certs:
        raise RuntimeError("No certificates found in PEM chain")
    cert = certs[0].encode()
    chain = "\n".join(certs[1:]).encode() if len(certs) > 1 else b""
    return cert, chain


def import_to_acm(acm_client, cert_pem, key_pem, chain_pem, existing_arn=None):
    """Import certificate into ACM. Re-imports in place if existing_arn is set.

    If re-import fails due to key-type mismatch (e.g. existing cert uses EC
    but new cert uses RSA), falls back to importing as a brand-new certificate.
    """
    params = {
        "Certificate": cert_pem,
        "PrivateKey": key_pem,
    }
    if chain_pem:
        params["CertificateChain"] = chain_pem
    if existing_arn:
        params["CertificateArn"] = existing_arn

    try:
        resp = acm_client.import_certificate(**params)
    except acm_client.exceptions.ValidationException:
        if existing_arn:
            logger.warning(
                "Re-import into %s failed (key type mismatch?), "
                "importing as new certificate", existing_arn,
            )
            params.pop("CertificateArn")
            resp = acm_client.import_certificate(**params)
        else:
            raise
    return resp["CertificateArn"]


def update_distribution_cert(cf_client, dist_id, cert_arn, dist_config, etag):
    dist_config["ViewerCertificate"] = {
        "ACMCertificateArn": cert_arn,
        "SSLSupportMethod": "sni-only",
        "MinimumProtocolVersion": "TLSv1.2_2021",
        "Certificate": cert_arn,
        "CertificateSource": "acm",
    }
    cf_client.update_distribution(
        Id=dist_id,
        DistributionConfig=dist_config,
        IfMatch=etag,
    )
    logger.info("Updated distribution %s with certificate %s",
                dist_id, cert_arn)


def process_distribution(dist_entry, acme_client, cf_client, acm_client, s3_client):
    dist_id = dist_entry["id"]
    logger.info("Processing distribution %s", dist_id)

    info = get_distribution_info(cf_client, dist_id)

    domains = dist_entry.get("domains") or info["domains"]
    s3_bucket = dist_entry.get("s3_bucket") or info["s3_bucket"]

    if not domains:
        raise RuntimeError(f"No domains found for distribution {dist_id}")
    if not s3_bucket:
        raise RuntimeError(f"No S3 bucket found for distribution {dist_id}")

    logger.info("Domains: %s, S3 bucket: %s", domains, s3_bucket)

    if not needs_renewal(acm_client, info["cert_arn"]):
        logger.info("Certificate for %s does not need renewal", dist_id)
        return SKIPPED

    logger.info("Renewing certificate for %s", dist_id)

    # Create ACME order
    order = acme_client.new_order(domains)

    # Fulfill HTTP-01 challenges
    challenges_to_clean = []
    try:
        for auth_url in order["authorizations"]:
            auth = acme_client.get_authorization(auth_url)
            if auth["status"] == "valid":
                continue

            challenge = acme_client.get_http01_challenge(auth)
            token = challenge["token"]
            key_auth = acme_client.key_authorization(token)

            upload_challenge(s3_client, s3_bucket, token, key_auth)
            challenges_to_clean.append((s3_bucket, token))

            acme_client.respond_to_challenge(challenge["url"])
            acme_client.poll_until_valid(auth_url, "authorization")

        # Generate CSR and finalize
        key_pem, csr_der = generate_csr(domains)
        order_result = acme_client.finalize_order(order["finalize"], csr_der)

        if order_result.get("status") != "valid":
            order_result = acme_client.poll_until_valid(order["url"], "order")

        # Download and import certificate
        cert_pem_chain = acme_client.download_certificate(
            order_result["certificate"])
        cert_pem, chain_pem = split_pem_chain(cert_pem_chain)

        cert_arn = import_to_acm(
            acm_client, cert_pem, key_pem, chain_pem,
            existing_arn=info["cert_arn"],
        )
        logger.info("Imported certificate: %s", cert_arn)

        # Re-fetch distribution config for fresh ETag
        fresh_info = get_distribution_info(cf_client, dist_id)
        update_distribution_cert(
            cf_client, dist_id, cert_arn,
            fresh_info["config"], fresh_info["etag"],
        )

        return RENEWED

    finally:
        for bucket, token in challenges_to_clean:
            try:
                delete_challenge(s3_client, bucket, token)
            except Exception as e:
                logger.warning("Failed to delete challenge %s: %s", token, e)


def lambda_handler(event, context):
    config = load_config()
    account_key = load_account_key()

    directory_url = config["acme"].get(
        "directory_url",
        "https://acme-v02.api.letsencrypt.org/directory",
    )
    acme_client = AcmeClient(directory_url, account_key)

    # ACM must be in us-east-1 for CloudFront
    acm_client = boto3.client("acm", region_name="us-east-1")
    cf_client = boto3.client("cloudfront")
    s3_client = boto3.client("s3")

    # Register ACME account (idempotent — retrieves existing account if already registered)
    acme_client.register(config["acme"]["email"])

    results = {}
    for dist_entry in config.get("distributions", []):
        dist_id = dist_entry["id"]
        try:
            result = process_distribution(
                dist_entry, acme_client, cf_client, acm_client, s3_client,
            )
            results[dist_id] = result
        except Exception as e:
            logger.error("Failed to process %s: %s", dist_id, e, exc_info=True)
            results[dist_id] = FAILED

    logger.info("Results: %s", results)
    return results
