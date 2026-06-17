package compliance.tagging

# Deny resources that are missing mandatory corporate cost tracking tags
deny[msg] {
    resource := input
    
    # Target S3 bucket configurations explicitly
    resource.resource_type == "aws_s3_bucket"
    
    # Check for missing tags completely or missing required keys
    not resource.tags.Environment
    msg := "TAGGING VIOLATION: Resource is missing the mandatory 'Environment' tracking tag."
}

deny[msg] {
    resource := input
    resource.resource_type == "aws_s3_bucket"
    not resource.tags.CostCenter
    msg := "TAGGING VIOLATION: Resource is missing the mandatory 'CostCenter' tracking tag."
}
