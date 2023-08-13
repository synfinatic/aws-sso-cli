# AWS SSO CLI
![Tests](https://github.com/synfinatic/aws-sso-cli/workflows/Tests/badge.svg)
[![codeql-analysis](https://github.com/synfinatic/aws-sso-cli/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/synfinatic/aws-sso-cli/actions/workflows/codeql-analysis.yml)
[![golangci-lint](https://github.com/synfinatic/aws-sso-cli/actions/workflows/golangci-lint.yaml/badge.svg)](https://github.com/synfinatic/aws-sso-cli/actions/workflows/golangci-lint.yaml)
[![Report Card Badge](https://goreportcard.com/badge/github.com/synfinatic/aws-sso-cli)](https://goreportcard.com/report/github.com/synfinatic/aws-sso-cli)
[![License Badge](https://img.shields.io/badge/license-GPLv3-blue.svg)](https://raw.githubusercontent.com/synfinatic/aws-sso-cli/main/LICENSE)
[![Codecov Badge](https://codecov.io/gh/synfinatic/aws-sso-cli/branch/main/graph/badge.svg?token=F8454GS4HS)](https://codecov.io/gh/synfinatic/aws-sso-cli)

 * [About](#about)
 * [How to read these docs](#how-to-read-these-docs)
 * [What does AWS SSO CLI do?](#what-does-aws-sso-cli-do)
 * [Demo](#demo)
 * [Security](#security)
 * [What next?](#what-next)
 * [License](#license)

Other Pages:

 * [Quick Start & Installation Guide](docs/quickstart.md)
 * [Running aws-sso](docs/commands.md)
 * [Configuration](docs/config.md)
 * [Security Policy](security.md)
 * [Frequently Asked Questions](docs/FAQ.md)
 * [Compared to AWS Vault](docs/aws-vault.md)
 * [Releases](https://github.com/synfinatic/aws-sso-cli/releases)
 * [Changelog](CHANGELOG.md)


## About

AWS SSO CLI is a secure replacement for using the [aws configure sso](
https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html)
wizard with a focus on security and ease of use for organizations with
many AWS Accounts and/or users with many IAM Roles to assume. It shares
a lot in common with [aws-vault](https://github.com/99designs/aws-vault),
but is more focused on the AWS SSO use case instead of static API credentials.
Check out [this page](docs/aws-vault.md) for more information on how these
two tools compare.

AWS SSO CLI requires your AWS account(s) to be setup with [AWS SSO](
https://aws.amazon.com/single-sign-on/)!  If your organization is using the
older SAML integration (typically you will have multiple tiles in OneLogin/Okta)
then this won't work for you.

## How to read these docs

In general, I do feature development in feature branches and then merge to
the `main` branch when that feature is stable.  I also tend to try to include
any documentation changes in those pull requests.  Once a release is ready,
I tag the tip of `main` and do the release.

What that means is that the documentation you see here (tip of `main`) may
include features that are not in the latest release.  To view the docs for
your release, please use the branch selector ![branch selector](
https://user-images.githubusercontent.com/1075352/167158202-93312c5c-cbb8-403f-9e2b-4eb34e2634f3.png)
near the top of this page to choose the tag of the version of AWS SSO CLI
that you are using.

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
to your shell environment in a variety of ways.

As part of the goal of improving the end-user experience with AWS SSO, it also
supports using [multiple AWS Web Console sessions](docs/quickstart.md#aws-console-access)
and many other quality of life improvements!

### Key Features

 * Enhanced security over stock AWS tooling
 * Auto-discover your AWS SSO roles and [manage](docs/commands.md#config)
     your `~/.aws/config` file
 * Support selecting an IAM role via `$AWS_PROFILE`, CLI (with auto-completion)
    or interactive search
 * Ability to select roles based on [user-defined](docs/config.md#tags)
    and auto-discovered tags
 * Support for [multiple active AWS Console sessions](docs/config.md#firefoxopenurlincontainer)
 * Guided setup to help you configure `aws-sso` the first time you run
 * Advanced configuration available to [adjust colors](docs/config.md#PromptColors)
    and generate [named profiles via templates](docs/config.md#ProfileFormat)
 * Easily see how much longer your STS credentials [are valid for](docs/commands.md#time)
 * Written in GoLang, so only need to install a single binary (no dependencies)
 * Supports Linux, MacOS, and Windows

## Demos

Here's a quick demo showing how to select a role to assume in interactive mode
and then run commands in that context (by default it starts a new shell):

[![asciicast](https://asciinema.org/a/462167.svg)](https://asciinema.org/a/462167)


`aws-sso` also allows you to open the AWS Console in your browser for a
given AWS SSO role:

![FirefoxContainers Demo](
https://user-images.githubusercontent.com/1075352/166165880-24f7c9af-a037-4e48-aa2d-342f2efe5ad7.gif)

Want to see more?  Check out the [other demos](docs/demos.md).

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

## What next?

The following pages will help get you started:

 * [Quick Start & Installation Guide](docs/quickstart.md)
 * [Running aws-sso](docs/commands.md)
 * [Configuration](docs/config.md)
 * [Frequently Asked Questions](docs/FAQ.md)

## License

AWS SSO CLI is licensed under the [GPLv3](LICENSE).
