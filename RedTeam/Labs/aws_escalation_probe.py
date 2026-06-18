"""
AWS Privilege Escalation Probe - exercises IAM escalation and S3 misconfiguration
paths against a LocalStack endpoint for blue-team training and detection engineering.

Usage:
    python aws_escalation_probe.py --endpoint http://localhost:4566 --scenario all
    python aws_escalation_probe.py --scenario iam_escalation
    python aws_escalation_probe.py --scenario s3_misconfig --endpoint http://localhost:4566
"""

import argparse
import datetime
import hashlib
import hmac
import json
import sys
import urllib.error
import urllib.parse
import urllib.request


def timestamp():
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def log(scenario, action, status, verdict, remediation):
    print(f"[{timestamp()}] scenario={scenario} action={action} status={status} verdict={verdict} remediation={remediation}")


def sign_v4(method, url, region, service, access_key, secret_key, payload=b"", extra_headers=None):
    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc
    path = parsed.path or "/"
    query = parsed.query

    now = datetime.datetime.utcnow()
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")

    payload_hash = hashlib.sha256(payload).hexdigest()
    headers = {"host": host, "x-amz-date": amz_date, "x-amz-content-sha256": payload_hash}
    if extra_headers:
        headers.update({k.lower(): v for k, v in extra_headers.items()})

    signed_headers = ";".join(sorted(headers.keys()))
    canonical_headers = "".join(f"{k}:{v}\n" for k, v in sorted(headers.items()))
    canonical_request = "\n".join([method, path, query, canonical_headers, signed_headers, payload_hash])

    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, credential_scope,
                                 hashlib.sha256(canonical_request.encode()).hexdigest()])

    def hmac_sha256(key, msg):
        return hmac.new(key, msg.encode(), hashlib.sha256).digest()

    signing_key = hmac_sha256(hmac_sha256(hmac_sha256(
        hmac_sha256(f"AWS4{secret_key}".encode(), date_stamp), region), service), "aws4_request")
    signature = hmac.new(signing_key, string_to_sign.encode(), hashlib.sha256).hexdigest()

    auth = (f"AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}")
    result = {k: v for k, v in headers.items()}
    result["Authorization"] = auth
    return result


def iam_request(endpoint, action, params, access_key="test", secret_key="test"):
    url = f"{endpoint}/"
    body_params = {"Action": action, "Version": "2010-05-08", **params}
    payload = urllib.parse.urlencode(body_params).encode()
    headers = sign_v4("POST", url, "us-east-1", "iam", access_key, secret_key, payload,
                       {"content-type": "application/x-www-form-urlencoded"})
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except Exception as e:
        return 0, str(e)


def s3_request(endpoint, method, bucket, key="", payload=b"", extra_headers=None, access_key="test", secret_key="test"):
    path = f"/{bucket}/{key}".rstrip("/")
    url = f"{endpoint}{path}"
    headers = sign_v4(method, url, "us-east-1", "s3", access_key, secret_key, payload, extra_headers)
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url, data=payload or None, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except Exception as e:
        return 0, str(e)


def run_iam_escalation(endpoint):
    user = "probe-test-user"
    status, _ = iam_request(endpoint, "CreateUser", {"UserName": user})
    log("iam_escalation", "CreateUser", status, "PASS" if status in (200, 409) else "FAIL",
        "Monitor CreateUser events; restrict iam:CreateUser to break-glass roles only")

    status, body = iam_request(endpoint, "AttachUserPolicy", {
        "UserName": user, "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"})
    log("iam_escalation", "AttachUserPolicy:AdministratorAccess", status,
        "ESCALATION_SUCCESS" if status == 200 else "BLOCKED",
        "Alert on iam:AttachUserPolicy with AdministratorAccess; require MFA for privileged policy attachment")

    status, body = iam_request(endpoint, "CreateAccessKey", {"UserName": user})
    log("iam_escalation", "CreateAccessKey", status,
        "CREDENTIAL_HARVESTED" if status == 200 else "BLOCKED",
        "Alert on iam:CreateAccessKey for non-service accounts; rotate keys on detection")

    status, body = iam_request(endpoint, "AddUserToGroup", {"UserName": user, "GroupName": "Administrators"})
    log("iam_escalation", "AddUserToGroup:Administrators", status,
        "ESCALATION_SUCCESS" if status == 200 else "BLOCKED",
        "Monitor iam:AddUserToGroup to privileged groups; implement SCPs restricting group membership changes")

    iam_request(endpoint, "DetachUserPolicy", {
        "UserName": user, "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"})
    iam_request(endpoint, "DeleteUser", {"UserName": user})


def run_s3_misconfig(endpoint):
    bucket = "probe-test-bucket"
    status, _ = s3_request(endpoint, "PUT", bucket)
    log("s3_misconfig", "CreateBucket", status, "PASS" if status in (200, 409) else "FAIL",
        "Enable S3 Block Public Access at account level to prevent accidental exposure")

    acl_payload = b'<AccessControlPolicy><AccessControlList><Grant><Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="Group"><URI>http://acs.amazonaws.com/groups/global/AllUsers</URI></Grantee><Permission>READ</Permission></Grant></AccessControlList></AccessControlPolicy>'
    status, _ = s3_request(endpoint, "PUT", bucket, "?acl", acl_payload,
                            {"Content-Type": "application/xml"})
    log("s3_misconfig", "PutBucketAcl:PublicRead", status,
        "MISCONFIGURATION_SET" if status in (200, 204) else "BLOCKED",
        "Enable S3 Block Public Access; alert on s3:PutBucketAcl granting AllUsers permissions")

    status, _ = s3_request(endpoint, "GET", bucket, "?policy")
    log("s3_misconfig", "GetBucketPolicy:MissingPolicy", status,
        "EXPOSED" if status == 404 else "POLICY_EXISTS",
        "Enforce bucket policies via AWS Config rule s3-bucket-policy-required")

    status, _ = s3_request(endpoint, "GET", bucket, "?encryption")
    log("s3_misconfig", "GetBucketEncryption:NoSSE", status,
        "UNENCRYPTED" if status == 404 else "ENCRYPTED",
        "Enforce SSE-KMS via bucket policy denying s3:PutObject without x-amz-server-side-encryption header")

    status, _ = s3_request(endpoint, "GET", bucket, "?versioning")
    log("s3_misconfig", "GetBucketVersioning:Disabled", status,
        "VERSIONING_OFF" if status in (200,) else "CHECK_FAILED",
        "Enable versioning and MFA Delete to protect against ransomware and accidental deletion")

    s3_request(endpoint, "DELETE", bucket)


def main():
    parser = argparse.ArgumentParser(description="AWS Privilege Escalation Probe against LocalStack")
    parser.add_argument("--endpoint", default="http://localhost:4566",
                        help="LocalStack endpoint URL (default: http://localhost:4566)")
    parser.add_argument("--scenario", choices=["all", "iam_escalation", "s3_misconfig"],
                        default="all", help="Scenario set to execute")
    parser.add_argument("--profile", default=None, help="AWS CLI profile (informational only)")
    args = parser.parse_args()

    if "localhost" not in args.endpoint and "127.0.0.1" not in args.endpoint and "0.0.0.0" not in args.endpoint:
        print(f"ERROR: endpoint '{args.endpoint}' does not appear to be a local address. "
              "This tool targets LocalStack only.", file=sys.stderr)
        sys.exit(1)

    print(f"[{timestamp()}] probe_start endpoint={args.endpoint} scenario={args.scenario} profile={args.profile or 'default'}")

    if args.scenario in ("all", "iam_escalation"):
        run_iam_escalation(args.endpoint)
    if args.scenario in ("all", "s3_misconfig"):
        run_s3_misconfig(args.endpoint)

    print(f"[{timestamp()}] probe_complete")


if __name__ == "__main__":
    main()