# Example only: scanned by the tests, never run.  CG-SEC-001 (safe)
import os

import boto3

AWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]


def client():
    return boto3.client("s3", aws_access_key_id=AWS_ACCESS_KEY_ID)
