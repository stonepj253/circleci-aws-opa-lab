package aws.s3.security

deny[msg] {
    input.resource_type == "aws_s3_bucket"
    not input.server_side_encryption_configuration
    msg := "S3 buckets must have server-side encryption enabled"
}
