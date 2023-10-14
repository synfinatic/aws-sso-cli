# Security Policy

## Supported Versions

The only version I support is the latest version of `aws-sso`.  Should a new
major version be released which is incompatible with v1.x, then this policy
will be updated at that time.

## Reporting a Vulnerability

Please open a [security ticket in GitHub](
https://github.com/synfinatic/aws-sso-cli/issues/new?assignees=&labels=security&projects=&template=bug_report.md&title=).
If you believe the public visibility of the information of the bug would
place other `aws-sso` users at risk, then you may email me at:
`synfinatic@gmail.com`.  GPG encrypting your email in those situations is
encouraged and you should use [this GPG Key](commit-sign-key.asc.md).

## Security Model

`aws-sso` relies on [99designs/keyring](https://github.com/99designs/keyring)
to store and retrieve secrets in 3rd party secure key stores which are
available on macOS, Windows, and Linux.  The security of `aws-sso` is
dependent on those systems.

AWS Identity Center security tokens are never exposed, however by design
the AWS IAM credentials are typically exposed via a variety of means in order
for them to be used by other processes.  It is the user's responsibility to
ensure that those credentials are handled appropriately based on their
security threat model.

### ECS Server Mode

When running in ECS Server Mode (`aws-sso ecs run`) an HTTP API will be
started on a TCP port bound to localhost.  Loading and retrieving
IAM Role credentials from this server will happen in the clear without
any encryption or authentication.  For this reason, it is not recommended
to be used on multi-tenant user systems or other untrusted environments.

Adding [encryption](https://github.com/synfinatic/aws-sso-cli/issues/518)
and [authentication](https://github.com/synfinatic/aws-sso-cli/issues/516)
are on the roadmap.  If these security features are interesting to you
please leave a comment.
