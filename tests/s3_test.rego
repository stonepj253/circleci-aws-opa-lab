package aws.s3.security

# Test that encrypted S3 bucket is allowed (deny should be empty)
test_encrypted_bucket_allowed {
    count(deny) == 0
    with input as {
        "resource_type": "aws_s3_bucket",
        "server_side_encryption_configuration": {
            "rule": {
                "apply_server_side_encryption_by_default": {
                    "sse_algorithm": "AES256"
                }
            }
        }
    }
}

# Test that unencrypted S3 bucket is denied (deny should have an error)
test_unencrypted_bucket_denied {
    deny["S3 buckets must have server-side encryption enabled"] with input as {
        "resource_type": "aws_s3_bucket"
    }
}

# Test that public-read bucket is denied
test_public_read_bucket_denied {
    deny["S3 buckets must not have public-read ACL"] with input as {
        "resource_type": "aws_s3_bucket",
        "acl": "public-read",
        "server_side_encryption_configuration": {}
    }
}
