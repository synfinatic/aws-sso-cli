# AWS SSO CLI
![Tests](https://github.com/synfinatic/aws-sso-cli/workflows/Tests/badge.svg)
[![codeql-analysis](https://github.com/synfinatic/aws-sso-cli/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/synfinatic/aws-sso-cli/actions/workflows/codeql-analysis.yml)
[![golangci-lint](https://github.com/synfinatic/aws-sso-cli/actions/workflows/golangci-lint.yaml/badge.svg)](https://github.com/synfinatic/aws-sso-cli/actions/workflows/golangci-lint.yaml)
[![Report Card Badge](https://goreportcard.com/badge/github.com/synfinatic/aws-sso-cli)](https://goreportcard.com/report/github.com/synfinatic/aws-sso-cli)
[![License Badge](https://img.shields.io/badge/license-GPLv3-blue.svg)](https://raw.githubusercontent.com/synfinatic/aws-sso-cli/main/LICENSE)
[![Codecov Badge](https://codecov.io/gh/synfinatic/aws-sso-cli/branch/main/graph/badge.svg?token=F8454GS4HS)](https://codecov.io/gh/synfinatic/aws-sso-cli)

[Documentation](https://synfinatic.github.io/aws-sso-cli/) | [ChangeLog](CHANGELOG.md) | [Releases](https://github.com/synfinatic/aws-sso-cli/releases) | [License](LICENSE.md)


AWS SSO CLI is a secure replacement for using the [aws configure sso](
https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html)
wizard with a focus on security and ease of use for organizations with
many AWS Accounts and/or users with many IAM Roles to assume. It shares
a lot in common with [aws-vault](https://github.com/99designs/aws-vault),
but is more focused on the AWS IAM Identity Center use case instead 
of static API credentials.

AWS SSO CLI requires your AWS account(s) to be setup with [AWS IAM Identity Center](
https://aws.amazon.com/iam/identity-center/), which was previously known as AWS Single Sign-On.
If your organization is using the older SAML integration (typically you will 
have multiple tiles in OneLogin/Okta) then this won't work for you.
