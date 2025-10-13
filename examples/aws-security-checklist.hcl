spec_version = "0.1.15"

// These are from https://d1.awsstatic.com/whitepapers/Security/AWS_Security_Checklist.pdf

component "control" "aws-iam-awsorgs" {
  description = "AWS accounts are managed with [AWS Organisations](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_introduction.html#features)"
}

component "control" "aws-iam-root" {
  description = "The root user is only used by exception, and has [MFA](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html#id_root-user_manage_mfa) enabled"
}

component "control" "aws-iam-accountcontacts" {
  description = "AWS Accounts have [account contacts](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts.html) configured"
}

component "control" "aws-iam-identityprovider" {
  description = "Identities are centralised with [AWS Single Sign-On](https://aws.amazon.com/single-sign-on/getting-started/) or [third-party provider](https://aws.amazon.com/security/partner-solutions/) to provide federated access"
}

component "control" "aws-iam-segregatedaccounts" {
  description = "Multiple AWS accounts are configured for separate environments (DEV, TEST, PROD)"
}

component "control" "aws-iam-secretsstorage" {
  description = "Where integrated AWS tokens can't be used, all secrets are stored in [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/)"
}

component "control" "aws-detection-cloudtrail" {
  description = "[Cloudtrail](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-receive-logs-from-multiple-accounts.html) is configured to log API activity"
}

component "control" "aws-detection-guardduty" {
  description = "[GuardDuty](https://aws.amazon.com/guardduty/) is configured for continuous monitoring"
}

component "control" "aws-detectin-securityhub" {
  description = "[Security Hub](https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html) is used to validate the security of all AWS accounts"
}

component "control" "aws-detection-applogs" {
  description = "Service level logging is enabled, such as [VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html) and [Server Access Logs](https://docs.aws.amazon.com/AmazonS3/latest/dev/ServerLogs.html)"
}

component "control" "aws-detection-configalerts" {
  description = "AWS Config is configured to send alerts on changes to resources"
}

component "control" "aws-detection-logalerting" {
  description = "AWS CloudTrail and GuardDuty are configured to send alerts"
}

component "control" "aws-infra-patching" {
  description = "[AWS Systems Manager Patch Manager](https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-patch.html) is configured to automate patching of all systems"
}

component "control" "aws-infra-ddos" {
  description = "[CloudFront](https://aws.amazon.com/cloudfront/), [WAF](https://aws.amazon.com/waf/), and [Shield](https://aws.amazon.com/shield/) are configured to provide prection against distributed denial of service attacks"
}

component "control" "aws-infra-subnetsegregation" {
  description = "Different resources are deployed into segregated subnets, with segmented Internet routing"
}

component "control" "aws-infra-securitygroups" {
  description = "[Security groups](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html) are configured to control inbound and outbound traffic"
}

component "control" "aws-encryption-s3" {
  description = "S3 buckets are configured with [encryption](https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingKMSEncryption.html)"
}

component "control" "aws-encryption-ebs" {
  description = "EBS volumes are configured with [encryption](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html#encryption-by-default)"
}

component "control" "aws-encryption-kms" {
  description = "[KMS](https://aws.amazon.com/kms/) is configured to protect data across AWS services and within applications"
}

component "control" "aws-encryption-tlscertmgr" {
  description = "Default encryption is configured for all network traffic, including TLS, by using [Certificate Manager](https://docs.aws.amazon.com/acm/latest/userguide/acm-overview.html)"
}
