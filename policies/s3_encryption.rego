package aws.s3

default allow = false

# Allow the deployment if there are no violations
allow {
    count(violations) == 0
}

# Catch any S3 bucket resource missing server-side encryption blocks
violations[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    
    # Check if encryption configuration is completely missing
    not resource.change.after.server_side_encryption_configuration
    
    msg := sprintf("SECURITY VIOLATION: S3 Bucket '%v' is missing mandatory server-side encryption settings.", [resource.name])
}
