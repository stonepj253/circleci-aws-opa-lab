package aws.s3.security

test_unencrypted_bucket_denied {
    deny["S3 buckets must have server-side encryption enabled"] with input as {
        "resource_type": "aws_s3_bucket"
    }
}
