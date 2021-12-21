# AWS SSO CLI
![Tests](https://github.com/synfinatic/aws-sso-cli/workflows/Tests/badge.svg)
[![Report Card](https://goreportcard.com/badge/github.com/synfinatic/aws-sso-cli)](https://goreportcard.com/report/github.com/synfinatic/aws-sso-cli)
[![GitHub license](https://img.shields.io/badge/license-GPLv3-blue.svg)](https://raw.githubusercontent.com/synfinatic/aws-sso-cli/main/LICENSE)

 * [About](#about)
 * [What does AWS SSO CLI do?](#what-does-aws-sso-cli-do)
 * [Demo](#demo)
 * [Installation](#installation)
 * [Quick Setup](#quick-setup)
 * [Security](#security)
 * [Commands](#commands)
 * [Configuration](docs/config.md)
 * [Environment Varables](#environment-varables)
 * [Release History](#release-history)
 * [License](#license)
 * [Frequently Asked Questions](docs/FAQ.md)


## About

AWS SSO CLI is a secure replacement for using the [aws configure sso](
https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html)
wizard with a focus on security and ease of use for organizations with
many AWS Accounts and/or users with many IAM Roles to assume.

AWS SSO CLI requires your AWS account(s) to be setup with [AWS SSO](
https://aws.amazon.com/single-sign-on/)!  If your organization is using the
older SAML integration (typically you will have multiple tiles in OneLogin/Okta)
then this won't work for you.

## What does AWS SSO CLI do?

AWS SSO CLI makes it easy to manage your shell environment variables allowing
you to access the AWS API using CLI tools.  Unlike the official AWS tooling,
the `aws-sso` command does not require defining named profiles in your
`~/.aws/config` (or anywhere else for that matter) for each and every role you
wish to assume and use.

Instead, it focuses on making it easy to select a role via CLI arguments or
via an interactive auto-complete experience with automatic and user-defined
metadata (tags) and exports the necessary [AWS STS Token credentials](
https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_use-resources.html#using-temp-creds-sdk-cli)
to your shell environment.

## Demo

Here's a quick demo showing how to select a role to assume in interactive mode
and then run commands in that context (by default it starts a new shell).

[![asciicast](https://asciinema.org/a/445604.svg)](https://asciinema.org/a/445604)

## Installation

 * Option 1: [Download binary](https://github.com/synfinatic/aws-sso-cli/releases)
    1. Copy to appropriate location and `chmod 755`
 * Option 2: [Download RPM or DEB package](https://github.com/synfinatic/aws-sso-cli/releases)
    1. Use your package manager to install (Linux only)
 * Option 3: Install via [Homebrew](https://brew.sh)
    1. Run `brew install synfinatic/aws-sso-cli/aws-sso-cli`
 * Option 4: Build from source:
    1. Install [GoLang](https://golang.org) v1.17+ and GNU Make
    1. Clone this repo
    1. Run `make` (or `gmake` for GNU Make)
    1. Your binary will be created in the `dist` directory
    1. Run `make install` to install in /usr/local/bin

Note that the release binaries and packages are not officially signed at this time so
systems may generate warnings.

## Quick Setup

After installation, running `aws-sso` with no arguments will cause it to automatically
run through the setup wizard and ask you a few questions to get started:

 * SSO Instance Name ([DefaultSSO](docs/config.md#DefaultSSO))
 * SSO Start URL ([StartUrl](docs/config.md#StartUrl))
 * AWS SSO Region ([SSORegion](docs/config.md#SSORegion))
 * Default region for connecting to AWS ([DefaultRegion](docs/config.md#DefaultRegion))
 * Default action to take with URls ([UrlAction](docs/config.md#UrlAction))
 * Maximum number of History items to keep ([HistoryLimit](docs/config.md#HistoryLimit))
 * Number of minutes to keep items in History ([HistoryMinutes](docs/config.md#HistoryMinutes))
 * Log Level ([LogLevel](docs/config.md#LogLevel))

After the guided setup, it is worth running:

`aws-sso install-completions`

to install autocomplete for your shell.

For more information about configuring `aws-sso` read the
[configuration guide](docs/config.md).  For more information about running
`aws-sso` see [commands](#commands).

### Windows Support

Window users are not the primary target for `aws-sso`, but I've found it generally
works better under `Command Prompt` a lot better than `PowerShell`.  If you are
a Windows user and experience any bugs, please open a [detailed bug report](
https://github.com/synfinatic/aws-sso-cli/issues/new).

## Security

Unlike the official [AWS cli tooling](https://aws.amazon.com/cli/), _all_
authentication tokens and credentials used for accessing AWS and your SSO
provider are encrypted on disk using your choice of secure storage solution.
All encryption is handled by the [99designs/keyring](https://github.com/99designs/keyring)
library.

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
 * Meta data associated with the AWS Roles fetched via AWS SSO in `~/.aws-sso/cache.json`
    * Email address tied to the account (root user)
    * AWS Account Alias
    * AWS Role ARN

## Commands

 * [cache](#cache) -- Force refresh of AWS SSO role information
 * [console](#console) -- Open AWS Console in a browser with the selected role
 * [eval](#eval) -- Print shell environment variables for use in your shell
 * [exec](#exec) -- Exec a command with the selected role
 * [flush](#flush) -- Force delete of cached AWS SSO credentials
 * [list](#list) -- List all accounts & roles
 * [process](#process) -- Generate JSON for AWS profile credential\_process option
 * [tags](#tags) -- List manually created tags for each role
 * [time](#time) -- Print how much time remains for currently selected role
 * [install-autocomplete](#install-autocomplete) -- Install auto-complete functionality into your shell
 * `version` -- Print the version of aws-sso

### Common Flags

 * `--help`, `-h` -- Builtin and context sensitive help
 * `--browser <path>`, `-b` -- Override default browser to open AWS SSO URL (`$AWS_SSO_BROWSER`)
 * `--config <file>` -- Specify alternative config file (`$AWS_SSO_CONFIG`)
 * `--level <level>`, `-L` -- Change default log level: [error|warn|info|debug|trace]
 * `--lines` -- Print file number with logs
 * `--url-action`, `-u` -- Print, open or copy URLs to clipboard
 * `--sso <name>`, `-S` -- Specify non-default AWS SSO instance to use (`$AWS_SSO`)
 * `--sts-refresh` -- Force refresh of STS Token Credentials

### console

Console generates a URL which will grant you access to the AWS Console in your
web browser.  The URL can be sent directly to the browser (default), printed
in the terminal or copied into the Copy & Paste buffer of your computer.

Flags:

 * `--region <region>`, `-r` -- Specify the `$AWS_DEFAULT_REGION` to use
 * `--arn <arn>`, `-a` -- ARN of role to assume (`$AWS_SSO_ROLE_ARN`)
 * `--account <account>`, `-A` -- AWS AccountID of role to assume (`$AWS_SSO_ACCOUNT_ID`)
 * `--duration <minutes>`, `-d` -- AWS Session duration in minutes (default 60)
 * `--prompt`, `-p` -- Force interactive prompt to select role
 * `--role <role>`, `-R` -- Name of AWS Role to assume (requires `--account`) (`$AWS_SSO_ROLE_NAME`)

The generated URL is good for 15 minutes after it is created.

The common flag `--url-action` is used both for AWS SSO authentication as well as
what to do with the resulting URL from the `console` command.

Priority is given to:

 * `--prompt`
 * `--arn` (`$AWS_SSO_ROLE_ARN`)
 * `--account` (`$AWS_SSO_ACCOUNT_ID`) and `--role` (`$AWS_SSO_ROLE_NAME`)
 * `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN` environment variables
 * Prompt user interactively

### eval

Generate a series of `export VARIABLE=VALUE` lines suitable for sourcing into your
shell.  Allows obtaining new AWS credentials without starting a new shell.  Can be
used to refresh existing AWS credentials or by specifying the appropriate arguments.

Suggested use (bash): `eval $(aws-sso eval <args>)`

Flags:

 * `--arn <arn>`, `-a` -- ARN of role to assume
 * `--account <account>`, `-A` -- AWS AccountID of role to assume (requires `--role`)
 * `--role <role>`, `-R` -- Name of AWS Role to assume (requires `--account`)
 * `--no-region` -- Do not set the AWS_DEFAULT_REGION from config.yaml
 * `--refresh` -- Refresh current IAM credentials

Priority is given to:

 * `--refresh` (Uses `$AWS_SSO_ROLE_ARN`)
 * `--arn`
 * `--account` and `--role`

**Note:** The `eval` command only honors the `$AWS_SSO_ROLE_ARN` in the context
of the `--refresh` flag.  The `$AWS_SSO_ROLE_NAME` and `$AWS_SSO_ACCOUNT_ID`
are always ignored.

**Note:** The `eval` command will never honor the `--url-action=print`
option as this will intefere with bash/zsh/etc ability to evaluate
the generated commands and will fall back to `--url-action=open`.

**Note:** The `eval` command is not supported under Windows CommandPrompt or PowerShell.

See [Environment Varables](#environment-varables) for more information about
what varibles are set.

### exec

Exec allows you to execute a command with the necessary [AWS environment variables](
https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html).  By default,
if no command is specified, it will start a new interactive shell so you can run multiple
commands.

Flags:

 * `--arn <arn>`, `-a` -- ARN of role to assume (`$AWS_SSO_ROLE_ARN`)
 * `--account <account>`, `-A` -- AWS AccountID of role to assume (`$AWS_SSO_ACCOUNT_ID`)
 * `--env`, `-e` -- Use existing ENV vars generated by AWS SSO to generate a URL
 * `--role <role>`, `-R` -- Name of AWS Role to assume (`$AWS_SSO_ROLE_NAME`)
 * `--no-region` -- Do not set the AWS_DEFAULT_REGION from config.yaml

Arguments: `[<command>] [<args> ...]`

Priority is given to:

 * `--arn` (`$AWS_SSO_ROLE_ARN`)
 * `--account` (`$AWS_SSO_ACCOUNT_ID`) and `--role` (`$AWS_SSO_ROLE_NAME`)
 * Prompt user interactively

You can not run `exec` inside of another `exec` shell.

See [Environment Varables](#environment-varables) for more information about what varibles are set.

### process

Process allows you to use AWS SSO as an [external credentials provider](
https://docs.aws.amazon.com/cli/latest/topic/config-vars.html#sourcing-credentials-from-external-processes)
with profiles defined in `~/.aws/config`.

Flags:

 * `--arn <arn>`, `-a` -- ARN of role to assume
 * `--account <account>`, `-A` -- AWS AccountID of role to assume
 * `--role <role>`, `-R` -- Name of AWS Role to assume (requires `--account`)

Priority is given to:

 * `--arn`
 * `--account` and `--role`

**Note:** The `process` command does not honor the `$AWS_SSO_ROLE_ARN`, `$AWS_SSO_ACCOUNT_ID`, or
`$AWS_SSO_ROLE_NAME` environment variables.

### cache

AWS SSO CLI caches information about your AWS Accounts, Roles and Tags for better
perfomance.  By default it will refresh this information after 24 hours, but you
can force this data to be refreshed immediately.

Cache data is also automatically updated anytime the `config.yaml` file is modified.

### list

List will list all of the AWS Roles you can assume with the metadata/tags available
to be used for interactive selection with `exec`.  You can control which fields are
printed by specifying the field names as arguments.

Flags:

 * `--list-fields`, `-f` -- List the available fields to print

Arguments: `[<field> ...]`

The arguments are a list of fields to display in the report.  Overrides the
defaults and/or the specified `ListFields` in the `config.yaml`.

Default fields:

 * `AccountId`
 * `AccountAlias`
 * `RoleName`
 * `ExpiresStr`

### flush

Flush any cached AWS SSO/STS credentials.  By default, it only flushes the SSO
credentials used to issue new STS tokens.

Flags:

 * `--all` -- Also delete any non-expired AWS STS credentials from secure store

### tags

Tags dumps a list of AWS SSO roles with the available metadata tags.

Flags:

 * `--account <account>` -- Filter results by AccountId
 * `--role <role>` -- Filter results by Role Name

By default the following key/values are available as tags to your roles:

 * `AccountID` -- AWS Account ID
 * `Role` -- AWS Role Name
 * `Email` -- Email address of root account associated with the AWS Account
 * `AccountName` -- Account Name for any role defined in config (see below)
 * `AccountAlias` --- AWS Account Alias defined by account administrator
 * `History` -- Tag tracking if this role was recently used.  See `HistoryLimit`
                in config.

### install-autocomplete

Configures your appropriate shell configuration file to add auto-complete
functionality for commands, flags and options.  Must restart your shell
for this to take effect.

## Environment Varables

### Honored Variables

The following environment variables are honored by `aws-sso`:

 * `AWS_SSO_FILE_PASSPHRASE` -- Passphrase to use with the `file` SecureStore
 * `AWS_SSO_CONFIG` -- Specify an alternate path to the `aws-sso` config file
 * `AWS_SSO_BROWSER` -- Override default browser for AWS SSO login
 * `AWS_SSO` -- Override default AWS SSO instance to use
 * `AWS_SSO_ROLE_NAME` -- Used for `--role`/`-R` with some commands
 * `AWS_SSO_ACCOUNT_ID` -- Used for `--account`/`-A` with some commands
 * `AWS_SSO_ROLE_ARN` -- Used for `--arn`/`-a` with some commands and with `eval --refresh`

The `file` SecureStore will use the `AWS_SSO_FILE_PASSPHRASE` environment
variable for the passphrase if it is set. (Not recommended.)

### Managed Variables

The following [AWS environment variables](
https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html)
are automatically set by `aws-sso`:

 * `AWS_ACCESS_KEY_ID` -- Authentication identifier required by AWS
 * `AWS_SECRET_ACCESS_KEY` -- Authentication secret required by AWS
 * `AWS_SESSION_TOKEN` -- Authentication secret required by AWS
 * `AWS_DEFAULT_REGION` -- Region to use AWS with (will never override an existing value)

The following environment variables are specific to `aws-sso`:

 * `AWS_SSO_ACCOUNT_ID` -- The AccountID for your IAM role
 * `AWS_SSO_ROLE_NAME` -- The name of the IAM role
 * `AWS_SSO_ROLE_ARN` -- The full ARN of the IAM role
 * `AWS_SSO_SESSION_EXPIRATION`  -- The date and time when the IAM role credentials will expire
 * `AWS_SSO_DEFAULT_REGION` -- Tracking variable for `AWS_DEFAULT_REGION`
 * `AWS_SSO_PROFILE` -- User customizable varible using the [ProfileFormat](#profileformat) template

## Release History

 * [Releases](https://github.com/synfinatic/aws-sso-cli/releases)
 * [Changelog](CHANGELOG.md)


## License

AWS SSO CLI is licnsed under the [GPLv3](LICENSE).
