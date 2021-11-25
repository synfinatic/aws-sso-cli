# AWS SSO CLI
![Tests](https://github.com/synfinatic/aws-sso-cli/workflows/Tests/badge.svg)
[![Report Card](https://goreportcard.com/badge/github.com/synfinatic/aws-sso-cli)](https://goreportcard.com/report/github.com/synfinatic/aws-sso-cli)
[![GitHub license](https://img.shields.io/badge/license-GPLv3-blue.svg)](https://raw.githubusercontent.com/synfinatic/aws-sso-cli/main/LICENSE)

 * [About](#about)
 * [What does AWS SSO CLI do?](#what-does-aws-sso-cli-do)
 * [Demo](#demo)
 * [Installation](#installation)
 * [Security](#security)
 * [Commands](#commands)
 * [Configuration](#configuration)
 * [Environment Varables](#environment-varables)
 * [Release History](#release-history)
 * [License](#license)


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
    1. Install [GoLang](https://golang.org) and GNU Make
    1. Clone this repo
    1. Run `make` (or `gmake` for GNU Make)
    1. Your binary will be created in the `dist` directory
    1. Run `make install` to install in /usr/local/bin

Note that the release binaries are not officially signed at this time so MacOS
and Windows systems may generate warnings.

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
 * `--use-sts`, `-s` -- Use existing STS credentials to generate a URL
 * `--role <role>`, `-R` -- Name of AWS Role to assume (requires `--account`) (`$AWS_SSO_ROLE_NAME`)

The generated URL is good for 15 minutes after it is created.

The common flag `--url-action` is used both for AWS SSO authentication as well as
what to do with the resulting URL from the `console` command.

Priority is given to:

 * `--arn` (`$AWS_SSO_ROLE_ARN`)
 * `--account` (`$AWS_SSO_ACCOUNT_ID`) and `--role` (`$AWS_SSO_ROLE_NAME`)
 * `--use-sts`
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

**Note:** The `eval` command only honors the `$AWS_SSO_ROLE_ARN` in the context of the `--refresh` flag.
The `$AWS_SSO_ROLE_NAME` and `$AWS_SSO_ACCOUNT_ID` are always ignored.

**Note:** The `eval` command will never honor the `--url-action=print`
option as this will intefere with bash/zsh/etc ability to evaluate
the generated commands and will fall back to `--url-action=open`.

See [Environment Varables](#environment-varables) for more information about what varibles are set.

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

## Configuration

By default, `aws-sso` stores it's configuration file in `~/.aws-sso/config.yaml`,
but this can be overridden by setting `$AWS_SSO_CONFIG` in your shell or via the
`--config` flag.

```yaml
SSOConfig:
    <Name of AWS SSO>:
        SSORegion: <AWS Region where AWS SSO is deployed>
        StartUrl: <URL for AWS SSO Portal>
        DefaultRegion: <AWS_DEFAULT_REGION>
        Accounts:  # optional block for specifying tags & overrides
            <AccountId>:
                Name: <Friendly Name of Account>
                DefaultRegion: <AWS_DEFAULT_REGION>
                Tags:  # tags for all roles in the account
                    <Key1>: <Value1>
                    <Key2>: <Value2>
                Roles:
                    <Role Name>:
                        DefaultRegion: <AWS_DEFAULT_REGION>
                        Tags:  # tags specific for this role (will override account level tags)
                            <Key1>: <Value1>
                            <Key2>: <Value2>

# See description below for these options
DefaultRegion: <AWS_DEFAULT_REGION>
Browser: <path to web browser>
DefaultSSO: <name of AWS SSO>
LogLevel: [error|warn|info|debug|trace]
LogLines: [true|false]
UrlAction: [print|open|clip]
ConsoleDuration: <minutes>
SecureStore: [file|keychain|kwallet|pass|secret-service|wincred|json]
JsonStore: <path to json file>
ProfileFormat: "<template>"
AccountPrimaryTag:
    - <tag 1>
    - <tag 2>
    - <tag N>
PromptColors:
    <Option 1>: <Color>
    <Option 2>: <Color>
    <Option N>: <Color>
HistoryLimit: <integer>
ListFields:
    - <field 1>
    - <field 2>
    - <field N>
```

### SSOConfig

This is the top level block for your AWS SSO instances.  Typically an organization
will have a single AWS SSO instance for all of their accounts under a single AWS master
payer account.  If you have more than one AWS SSO instance, then `Default` will be
the default unless overridden with `DefaultSSO`.

The `SSOConfig` config block is required.

### StartUrl

Each AWS SSO instance has a unique start URL hosted by AWS for interacting with your
SSO provider (Okta/OneLogin/etc).

The `StartUrl` is required.

### SSORegion

Each AWS SSO instance is configured in a specific AWS region which needs to be set here.

The `SSORegion` is required.

### DefaultRegion

The `DefaultRegion` allows you to define a value for the `$AWS_DEFAULT_REGION` when switching to a role.
Note that, aws-sso will NEVER change an existing `$AWS_DEFAULT_REGION` set by the user.

`DefaultRegion` can be specified at the following levels and the first match is selected:

 1. `SSOConfig -> <Name of the AWS SSO> -> Accounts -> <AccountId> -> Roles -> <RoleName>`
 1. `SSOConfig -> <Name of the AWS SSO> -> Accounts -> <AccountId>`
 1. `SSOConfig -> <Name of AWS SSO>`
 1. Top level of the file

### Accounts

The `Accounts` block is completely optional!  The only purpose of this block
is to allow you to add additional tags (key/value pairs) to your accounts/roles
to make them easier to select.

### Options

#### Browser / UrlAction

`UrlAction` gives you control over how AWS SSO and AWS Console URLs are opened in a browser:

 * `print` -- Prints the URL in your terminal
 * `open` -- Opens the URL in your default browser or the browser you specified via `--browser` or `Browser`
 * `clip` -- Copies the URL to your clipboard

If `Browser` is not set, then your default browser will be used.  Note that
your browser needs to support Javascript for the AWS SSO user interface.

#### DefaultSSO

If you only have a single AWS SSO instance, then it doesn't really matter what you call it,
but if you have two or more, than `Default` is automatically selected unless you manually
specify it here, on the CLI (`--sso`), or via the `AWS_SSO` environment variable.

#### LogLevel / LogLines

By default, the `LogLevel` is 'warn'.  You can override it here or via `--log-level` with one
of the following values:

 * `error`
 * `warn`
 * `info`
 * `debug`
 * `trace`

`LogLines` includes the file name/line and module name with each log for advanced debugging.

#### ConsoleDuration

By default, the `console` command opens AWS Console sessions which are valid for 60 minutes.
If you wish to override the default session duration, you can specify the number of minutes here
or with the `--duration` flag.

#### SecureStore / JsonStore

`SecureStore` supports the following backends:

 * `file` - Encrypted local files (OS agnostic and default)
 * `keychain` - macOS [Keychain](https://support.apple.com/guide/mac-help/use-keychains-to-store-passwords-mchlf375f392/mac)
 * `kwallet` - [KDE Wallet](https://utils.kde.org/projects/kwalletmanager/)
 * `pass` - [pass](https://www.passwordstore.org)
 * `secret-service` - Freedesktop.org [Secret Service](https://specifications.freedesktop.org/secret-service/latest/re01.html)
 * `wincred` - Windows [Credential Manager](https://support.microsoft.com/en-us/windows/accessing-credential-manager-1b5c916a-6a16-889f-8581-fc16e8165ac0)
 * `json` - Cleartext JSON file (very insecure and not recommended).  Location can be overridden with `JsonStore`

#### ProfileFormat

AWS SSO CLI can set an environment variable named `AWS_SSO_PROFILE` with
any value you can express using a [Go Template](https://pkg.go.dev/text/template)
which can be useful for modifying your shell prompt and integrate with your own
tooling.

The following variables are accessible from the `AWSRoleFlat` struct:

 * `Id` -- Unique integer defined by AWS SSO CLI for this role
 * `AccountId` -- AWS Account ID (int64)
 * `AccountAlias` -- AWS Account Alias defined in AWS
 * `AccountName` -- AWS Account Name defined in AWS or overridden in AWS SSO's config
 * `EmailAddress` -- Root account email address associated with the account in AWS
 * `Expires` -- When your API credentials expire (string)
 * `Arn` -- AWS ARN for this role
 * `RoleName` -- The role name
 * `Profile` -- Manually configured AWS_SSO_PROFILE value for this role
 * `DefaultRegion` -- The manually configured default region for this role
 * `SSORegion` -- The AWS Region where AWS SSO is enabled in your account
 * `StartUrl` -- The AWS SSO start URL for your account
 * `Tags` -- Map of additional custom key/value pairs
<!--
issue: #38
 * `Via` -- Role AWS SSO CLI will assume before assuming this role
-->

The following functions are available in your template:

 * `AccountIdStr(x)` -- Converts an AWS Account ID to a string
 * `EmptyString(x)` -- Returns true/false if the value `x` is an empty string
 * `FirstItem([]x)` -- Returns the first item in a list that is not an empty string
 * `StringsJoin([]x, y)` -- Joins the items in `x` with the string `y`

**Note:** Unlike most values stored in the `config.yaml`, because `ProfileFormat`
values often start with a `{` you will need to quote the value for it to be valid
YAML.

#### AccountPrimaryTag

When selecting a role, if you first select by role name (via the `Role` tag) you will
be presented with a list of matching ARNs to select. The `AccountPrimaryTag` automatically
includes another tag name and value as the description to aid in role selection.  By default
the following tags are searched (first match is used):

 * `AccountName`
 * `AccountAlias`
 * `Email`

Set `AccountPrimaryTag` to an empty list to disable this feature.

#### PromptColors

`PromptColors` takes a map of prompt options and color options allowing you to have
complete control of how AWS SSO CLI looks.  You only need to specify the options you wish
to override, but do not include the `PromptColors` if you have no options.  More information
about the meaning and use of the options below, [refer to the go-prompt docs](
https://pkg.go.dev/github.com/c-bata/go-prompt#Option).

Valid options:

 * `DescriptionBGColor`
 * `DescriptionTextColor`
 * `InputBGColor`
 * `InputTextColor`
 * `PrefixBackgroundColor`
 * `PrefixTextColor`
 * `PreviewSuggestionBGColor`
 * `PreviewSuggestionTextColor`
 * `ScrollbarBGColor`
 * `ScrollbarThumbColor`
 * `SelectedDescriptionBGColor`
 * `SelectedDescriptionTextColor`
 * `SelectedSuggestionBGColor`
 * `SelectedSuggestionTextColor`
 * `SuggestionBGColor`
 * `SuggestionTextColor`

Valid low intensity colors:

 * `Black`
 * `DarkRed`
 * `DarkGreen`
 * `Brown`
 * `DarkBlue`
 * `Purple`
 * `Cyan`
 * `LightGrey`

Valid high intensity colors:

 * `DarkGrey`
 * `Red`
 * `Green`
 * `Yellow`
 * `Blue`
 * `Fuchsia`
 * `Turquoise`
 * `White`

#### HistoryLimit

Limits the number of recently used roles tracked via the History tag.
Default is last 10 unique roles.  Set to 0 to disable.

#### ListFields

Specify which fields to display via the `list` command.  Valid options are:

 * `Id` -- Unique row identifier
 * `AccountId` -- AWS Account Id
 * `AccountName` -- Account Name from config.yaml
 * `AccountAlias` -- Account Name from AWS SSO
 * `ARN` -- Role ARN
 * `DefaultRegion` -- Configured default region
 * `EmailAddress` -- Email address of root account associated with AWS Account
 * `ExpiresEpoch` -- Unix epoch time when cached STS creds expire
 * `ExpiresStr` -- Hours and minutes until cached STS creds expire
 * `RoleName` -- Role name
 * `SSORegion` -- Region of AWS SSO instance
 * `StartUrl` -- AWS SSO Start Url
<!--
 * `Profile` -- ???
 * `Via` -- Previous ARN of role to assume
-->

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

### Set Variables

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
