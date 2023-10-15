## About

AWS SSO CLI is a secure replacement for using the [aws configure sso](
https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html)
wizard with a focus on security and ease of use for organizations with
many AWS Accounts and/or users with many IAM Roles to assume. It shares
a lot in common with [aws-vault](https://github.com/99designs/aws-vault),
but is more focused on the AWS SSO use case instead of static API credentials.

AWS SSO CLI requires your AWS account(s) to be setup with [AWS IAM Identity Center](
https://aws.amazon.com/iam/identity-center/), which was previously known as
AWS Single Sign-On.  If your organization is using the older SAML integration
(typically you will have multiple tiles in OneLogin/Okta) then this won't work for you.

## What does AWS SSO CLI do?

### Overview

AWS SSO CLI makes it easy to manage your shell environment variables allowing
you to access the AWS API & web console using CLI tools.  Unlike the official
AWS tooling, the `aws-sso` command does not require manually creating named
profiles in your `~/.aws/config` (or anywhere else for that matter) for each
and every role you wish to assume and use.

`aws-sso` focuses on making it easy to select a role via CLI arguments or
via an interactive auto-complete experience with automatic and user-defined
metadata (tags) and exports the necessary [AWS STS Token credentials](
https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_use-resources.html#using-temp-creds-sdk-cli)
to your shell environment in a variety of ways.  It even supports sharing
credentials via the [AWS ECS Task IAM Role](ecs-server.md).

As part of the goal of improving the end-user experience with AWS SSO, it also
supports using [multiple AWS Web Console sessions](quickstart.md#aws-console-access)
and many other quality of life improvements!

### Key Features

 * Enhanced security over stock AWS tooling
 * Auto-discover your AWS SSO roles and [manage](commands.md#config)
     your `~/.aws/config` file
 * Support selecting an IAM role via `$AWS_PROFILE`, CLI (with auto-completion)
    or interactive search
 * Ability to select roles based on [user-defined](config.md#tags)
    and auto-discovered tags
 * Support for [multiple active AWS Console sessions](quickstart.md#aws-console-access)
 * Guided setup to help you configure `aws-sso` the first time you run
 * Advanced configuration available to [adjust colors](config.md#PromptColors)
    and generate [named profiles via templates](config.md#ProfileFormat)
 * Easily see how much longer your STS credentials [are valid for](commands.md#time)
 * Written in GoLang, so only need to install a single binary (no dependencies)
 * Supports Linux, MacOS, and Windows


## Security

Unlike the official [AWS cli tooling](https://aws.amazon.com/cli/), _all_
authentication tokens and credentials used for accessing AWS and your SSO
provider are encrypted on disk using your choice of secure storage solution.
All encryption is handled by the [99designs/keyring](https://github.com/99designs/keyring)
library which is also used by [aws-vault](https://github.com/99designs/aws-vault).

Credentials encrypted by `aws-sso` and not via the standard AWS CLI tool:

 * AWS SSO ClientID/ClientSecret -- `~/.aws/sso/cache/botocore-client-id-<region>.json`
 * AWS SSO AccessToken -- `~/.aws/sso/cache/<random>.json`
 * AWS Profile Access Credentials -- `~/.aws/cli/cache/<random>.json`

As you can see, not only does the standard AWS CLI tool expose the temporary
AWS access credentials to your IAM roles, but more importantly the SSO
AccessToken which can be used to fetch IAM credentials for any role you have
been granted access!

### What is not encrypted?

 * Contents of user defined `~/.aws-sso/config.yaml`
 * Metadata associated with the AWS Roles fetched via AWS SSO in `~/.aws-sso/cache.json`
    * Email address tied to the account (root user)
    * AWS Account Alias
    * AWS Role ARN
