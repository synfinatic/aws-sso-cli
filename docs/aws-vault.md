# AWS SSO CLI vs AWS Vault

## Overview

Note: I believe this page to be accurate as of `aws-vault` v6.3.1 and
`aws-sso` v1.9.0. If you believe anything on this page is in error, please [let me know](
https://github.com/synfinatic/aws-sso-cli/issues/new?title=Documentation+error:)!

I get asked a lot why you should use AWS SSO CLI over [AWS Vault](
https://github.com/99designs/aws-vault) so I decided to write up this comparison.

First, I really like `aws-vault`, I've used in the past and really love
how it fixes a lot of the security issues related to the standard
AWS CLI tooling. Overall, it's got a great and useful feature set!

However, AWS SSO CLI is focused on integrating with [AWS SSO](
https://docs.aws.amazon.com/singlesignon/latest/userguide/what-is.html).  If
you're using the older [SAML integration](
https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_saml.html)
then neither `aws-vault` or `aws-sso` are going to help.  If you're still
using static AWS API Keys (storing them in your `~/.aws/credentials` file) then
`aws-vault` clearly has the strongest feature set today, but I hope to address
that in the near future.

Last, I want to point out that my tool uses the same [secure storage library](
https://github.com/99designs/keyring) that 99designs wrote for `aws-vault`
so thanks to them for making that available!

## How AWS Vault and the AWS CLI v2 tooling works

Because of it's early focus on securely managing [static AWS API
credentials](
https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html)
and integration with the existing `~/.aws/config` file, `aws-vault` still is
weighed down with the limitations of syntax and structure of the `~/.aws/config`
file.

For smaller organizations with few AWS accounts and less advanced
least priviledge access policies where users are not always assuming different
roles with only the permissions they need to complete at task, this
fundamentally works just fine.

But as your organization grows and you start implimenting more advanced
workflows, where users (especially in cross-functional organizations like
centralized Operations and Security teams) may need to access dozens or
even hundreds of AWS accounts and even more AWS roles to choose from,
the standard AWS tooling and configuration file really shows its warts.

This is also where existing AWS customers start looking at migrating to AWS SSO
because it just scales and generally works better.

On top of this, the standard `~/.aws/config` file's support for AWS SSO
was done in a way which made the Amazon developers lives easier, but not
the user.  For example for every AWS Role you wish to assume via AWS SSO
you have to write a block like this (`aws-vault` or AWS CLI v2):

```ini
[profile MyUniqueProfileName]
sso_start_url = https://foobar.awsapps.com/start
sso_region = us-east-1
sso_account_id = 012345678912
sso_role_name = MyRoleName
```

If you have 10 roles, that's 10 blocks.  Or 100 roles, well it's 100 blocks.
And every time you are given access to a new role (maybe a new AWS Account?)
you have to go in, select a unique profile name and write the block. At some
point users start complaining because this is "unmanageable" and "hard to use".

But remember it's called _Single Sign On_... why are we defining generally
global values like `sso_start_url` or `sso_region` over and over again?

Also, because of how SSO works with [PermissionSets](
https://docs.aws.amazon.com/singlesignon/latest/userguide/permissionsetsconcept.html),
it's quite likely a user will have the same `sso_role_name` in many different
AWS Accounts but we have a flat namespace of `profile` names to work with. This
might work fine for users who only need to access a handful of accounts
and roles, but at scale (and AWS SSO is obviously designed for larger
organizations) this becomes a problem that each user must deal with and
neither AWS CLI tooling or `aws-vault` really provide any substantive help.

## How AWS SSO CLI is different

AWS SSO CLI on the otherhand started life focused on integrating with AWS SSO.
I made the decision early on to support accessing AWS SSO Roles
without requiring the user to make any changes to their `~/.aws/config` file
and want to create a user experience that is a joy to use as their organization
grows.

The result is that:

 1. Users define their AWS SSO Instance values (`StartUrl` and `SSORegion`)
    only once. And yes, multiple SSO Instances are supported!
 1. Users are not required to pre-define the AWS Accounts or Roles they
    wish to access.  This is auto-discovered by `aws-sso` via the AWS API.
 1. The `aws-sso` configuration file has a simple hierarchy which eliminates
    the need to repeat the same configuration block or statements.
    Don't repeat yourself!
 1. Naming is hard!  Instead of forcing you to give each role a single unique
    name, `aws-sso` offers multiple ways to select a role at any time:
    * Users can select a role via an interactive search prompt using tags-
        just like you have with Gmail.  Tags include all the metadata that the
        AWS SSO API exposes as well as any user defined key/value pairs.
    * For people who don't like interactive searches, you can select using
        a `profile` value which is automatically generated via a powerful
        template engine OR by any user defined value.  Yes, you can even use
        the template for some roles and the user defined `profile` name for
        your most commonly used roles.
    * You can always select via standardized values like the Role ARN or
        AccountId and RoleName.
    * Of course, non-interactive (CLI) selection of roles supports
        tab-completion!
 1. Migrating to AWS SSO?  `aws-sso` is here to help.  It supports
    discovering all your AWS SSO roles and writing entries to your
    `~/.aws/config` file for you.  Now you can set your `$AWS_PROFILE`
    (or `--profile` flag) and take advantage of securely storing all your
     credentials.

If this sounds interesting, maybe it's worth checking out [the demos](demos.md)
or jumping ahead to the [Quickstart Guide](quickstart.md) to get it installed
and configured!

## Feature Comparison

| Feature                 | aws-vault | aws-sso   | AWS CLI v2 |
|-------------------------|-----------|-----------|------------|
| Secure store creds      | Yes       | Yes       | No         |
| Static AWS API Creds    | Yes       | No        | Yes        |
| SAML auth support       | No        | No        | No         |
| AWS SSO support         | Yes       | Yes       | Yes        |
| Web Identity support    | Yes       | No        | Yes        |
| Open AWS web console    | Yes       | Yes       | No         |
| Bulk SSO Role discovery | No        | Yes       | No         |
| Read ~/.aws/config      | Yes       | No        | Yes        |
| Write ~/.aws/config     | No        | Yes       | Yes        |
| User defined ENV vars   | No        | Yes       | No         |
| $AWS\_PROFILE templates | No        | Yes       | No         |
| Role chaining           | Yes       | Yes       | Yes        |
| CLI auto-complete       | Yes       | Yes       | Yes        |
| EC2/ECS Metadata server | Yes       | Yes       | No         |
| Firefox Containers      | No        | Yes       | No         |
| Exec new shell with AWS creds    | Yes  | Yes   | No     |
| Detect $AWS\_PROFILE collision   | No   | Yes   | Yes    |
| Add AWS creds into current shell | No   | Yes   | No     |


| Select Role Via      | aws-vault | aws-sso | AWS CLI v2 |
|----------------------|-----------|---------|------------|
| $AWS\_PROFILE        | Yes       | Yes     | Yes        |
| Profile name (CLI)   | Yes       | Yes     | Yes        |
| Tags                 | No        | Yes     | No         |
| Role ARN             | No        | Yes     | No         |
| AccountId & RoleName | No        | Yes     | No         |
