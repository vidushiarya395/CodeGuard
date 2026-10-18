# Example only: scanned by the tests, never run.  CG-SEC-001 (vulnerable)
# AKIAIOSFODNN7EXAMPLE is the example key ID from AWS's own documentation, not a real key.
import boto3

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"


def client(secret):
    return boto3.client("s3", aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=secret)
