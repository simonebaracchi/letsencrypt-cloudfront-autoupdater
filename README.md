# letsencrypt-cloudfront-autoupdater

Automatically renew and deploy [Let's Encrypt](https://letsencrypt.org/) SSL certificates for AWS CloudFront distributions, running as an AWS Lambda function.

## How It Works

1. **Scheduled trigger** — An EventBridge rule invokes the Lambda every **3 weeks**, leaving room for a retry before Let's Encrypt certificates expire (90-day lifetime, renewable within the last 30 days).
2. **Certificate check** — For each configured CloudFront distribution, the tool reads the current certificate from ACM and determines if renewal is needed.
3. **HTTP-01 challenge** — A new certificate is requested from Let's Encrypt via the ACME v2 protocol. The HTTP-01 challenge is used: a challenge token is uploaded to the distribution's S3 origin under `.well-known/acme-challenge/`. Let's Encrypt then verifies the token by making an HTTP request to the domain through CloudFront.
4. **Cleanup** — The challenge object is deleted from S3 immediately after verification. Objects are also uploaded with a 1-hour `Expires` header as a safety net.
5. **Import & deploy** — The issued certificate (and chain) is imported into ACM in `us-east-1` (required for CloudFront) and the CloudFront distribution is updated to use it.

## Why HTTP-01 (not DNS-01)

The DNS-01 challenge would require programmatic access to the DNS provider (e.g. Route 53). This tool avoids that dependency by using the HTTP-01 challenge instead — uploading a verification file to the S3 bucket that CloudFront already serves. This keeps the permission surface small and avoids coupling to any specific DNS provider.

## Bootstrapping

Cloudfront requires a SSL certificate to serve files, we need the file to pass the HTTP-01 challenge to get the SSL certificate.

To solve this chicken-and-egg problem, the first SSL certificate should still be obtained with DNS challenge. In case you are requesting a certificate for more than one domain, list all of them.

```bash
# certbot certonly --manual --preferred-challenges dns -d <domain> [-d <domain> [...]]
```

Note that usually `<domain>` should include `www.`, and consequently, the DNS TXT entry typically looks like `_acme-challenge.www` in your DNS provider. When asking for multiple domains, more DNS TXT entries will be needed.

The `fullchain.pem` and `privkey.pem` files can then be used to setup ACM:

```bash
# cat /etc/letsencrypt/live/DOMAIN-NAME/fullchain.pem
# cat /etc/letsencrypt/live/DOMAIN-NAME/privkey.pem
```

The first part of `fullchain.pem` is the certificate body, the second part is the certificate chain (mentioned as optional in ACM, but mandatory here). If you are creating a certificate for more domains, the first part will be the certificate body, and everything else is the certificate chain. The contents of `privkey.pem` are the certificate private key. Make extra-sure that you are importing the certificate in the `us-east-1` region of ACM. Then you can add the domain in CloudFront.


## Prerequisites

- **AWS account** with an IAM execution role using the permissions defined in [`iam-policy.json`](iam-policy.json) (see [IAM Role Setup](#iam-role-setup)).
- **S3 bucket** serving as the origin for your CloudFront distribution(s).
- **CloudFront distribution** configured with:
  - Your custom domain(s) as alternate domain names (CNAMEs).
  - The S3 bucket as an origin.
  - A behavior that serves the `.well-known/acme-challenge/*` path from the S3 origin (must not require HTTPS-only viewer protocol — Let's Encrypt follows redirects, but the path must be reachable).
- **ACM** — Certificates are imported into ACM in the **us-east-1** region (CloudFront requirement).

## Configuration

The tool reads a YAML configuration file (`config.yaml`) bundled in the Lambda deployment package. See [`config.example.yaml`](config.example.yaml) for the full reference.

```yaml
lambda:
  function_name: "letsencrypt-cloudfront-autoupdater"
  role_arn: "arn:aws:iam::123456789012:role/letsencrypt-cloudfront-autoupdater"
  region: "us-east-1"

acme:
  email: "admin@example.com"

distributions:
  - id: "E1234567890ABC"
```

Key sections:

| Section | Purpose |
|---|---|
| `lambda` | Deployment settings used by `deploy.sh`: function name, IAM role ARN, and region. |
| `acme` | Let's Encrypt account settings: contact email and ACME directory URL. |
| `distributions` | List of CloudFront distribution IDs to manage. Domains and S3 bucket are auto-detected from the distribution config, but can be overridden. |

No AWS credentials are stored in the config. The Lambda uses its **execution role** for all AWS API calls (see [IAM Role Setup](#iam-role-setup)).

### Why enumerate distributions (not S3 buckets)

A CloudFront distribution references its S3 origin, so the tool can auto-discover the bucket. The reverse is not true — an S3 bucket has no reference to CloudFront. Listing distribution IDs is therefore the simplest and least redundant approach.

## IAM Role Setup

The Lambda uses an **IAM execution role** — no IAM user or API keys are needed. AWS automatically provides temporary credentials to the Lambda at runtime via STS.

Create the role and attach the permissions policy:

```bash
# Create the role with the Lambda trust policy
aws iam create-role \
    --role-name letsencrypt-cloudfront-autoupdater \
    --assume-role-policy-document file://trust-policy.json

# Attach the permissions policy
aws iam put-role-policy \
    --role-name letsencrypt-cloudfront-autoupdater \
    --policy-name letsencrypt-cloudfront-autoupdater-policy \
    --policy-document file://iam-policy.json
```

The role ARN from the output (e.g. `arn:aws:iam::123456789012:role/letsencrypt-cloudfront-autoupdater`) goes into `config.yaml` under `lambda.role_arn`. The deploy script assigns it to the Lambda automatically.

Included policy files:

- [`trust-policy.json`](trust-policy.json) — allows Lambda to assume the role.
- [`iam-policy.json`](iam-policy.json) — minimal permissions: S3 writes restricted to `.well-known/acme-challenge/*`, ACM scoped to `us-east-1`, CloudFront read/update, CloudWatch Logs.

## Deployment

### Quick start

```bash
# 1. Copy and edit the config
cp config.example.yaml config.yaml
# Edit config.yaml — set your role ARN, email, and distribution IDs

# 2. Deploy (builds package, creates/updates Lambda, sets up EventBridge schedule)
./deploy.sh --profile <aws-deployer-profile>

# 3. Test manually
aws lambda invoke --function-name letsencrypt-cloudfront-autoupdater --region us-east-1 --profile <aws-deployer-profile> /dev/stdout
```

### What deploy.sh does

1. **Generates an ACME account key** (`account.key`) on first run — reused for subsequent deploys.
2. **Installs Python dependencies** into a `build/` directory and packages everything into `dist/deployment.zip`.
3. **Creates or updates the Lambda function** with the role ARN from `config.yaml`, Python 3.12 runtime, 15-minute timeout.
4. **Creates an EventBridge rule** (`rate(21 days)`) and grants it permission to invoke the Lambda.

### S3 bucket configuration

Ensure the S3 bucket has no lifecycle rule that would delete `.well-known/acme-challenge/*` objects before the Lambda can clean them up. As an optional safety net, you can add a lifecycle rule to expire objects under that prefix after **1 day** (the minimum S3 allows) to garbage-collect any orphaned challenge files.

## Architecture

```
EventBridge (rate: 21 days)
        │
        ▼
   Lambda Function
        │
        ├── 1. Read config.yaml
        ├── 2. For each distribution:
        │       ├── Get distribution config (CloudFront API)
        │       ├── Check current cert expiration (ACM API)
        │       ├── Request new cert (ACME / Let's Encrypt)
        │       ├── Upload HTTP-01 challenge to S3
        │       ├── Wait for ACME validation
        │       ├── Delete challenge from S3
        │       ├── Import new cert into ACM (us-east-1)
        │       └── Update distribution with new cert (CloudFront API)
        │
        └── 3. Log results to CloudWatch
```

## License

MIT
