# AWS SSO CLI

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
 * Meta data associated with the AWS Roles fetched via AWS SSO in `/.aws-sso/cache.json`
	* Email address of account
	* AWS Account Alias
	* AWS Role ARN

## Installation

 * Option 1: [Download binary](https://github.com/synfinatic/aws-sso-cli/releases)
 * Option 2: Build from source:
	1. Install [GoLang](https://golang.org) and GNU Make
	1. Clone this repo
	1. Run `make` (or `gmake` for GNU Make)
	1. Your binary will be created in the `dist` directory

In both cases, copy the binary to a reasonable location (such as `/usr/local/bin`) and
ensure that it is executable (`chmod 755 <path>`) and owned by root (`chown root <path>`).

Note that the release binaries are not signed at this time so MacOS and Windows systems
may generate warnings.

## Commands

 * `cache` -- Force refresh of AWS SSO role information
 * `console` -- Open AWS Console in a browser with the selected role
 * `exec` -- Exec a command with the selected role
 * `flush` -- Force delete of cached AWS SSO credentials
 * `list` -- List all accounts & roles
 * `renew` -- Renew current AWS SSO credentials
 * `tags` -- List manually created tags for each role
 * `time` -- Print how much time remains for currently selected role
 * `version` -- Print the version of aws-sso

### Common Flags

 * `--help`, `-h` -- Builtin and context sensitive help
 * `--level <level>`, `-L` -- Change default log level: [error|warn|info|debug|trace]
 * `--lines` -- Print file number with logs
 * `--config <file>`, `-c` -- Specify alternative config file
 * `--browser <path>`, `-b` -- Override default browser to open AWS SSO URL
 * `--url-action`, `-u` -- Print, open or put URLs in clipboard
 * `--region <region>, `-r` -- Specify the AWS_DEFAULT_REGION to use
 * `--sso <name>`, `-S` -- Specify non-default AWS SSO instance to use
 * `--sts-refresh` -- Force refresh of STS Token Credentials

### console

Console generates a URL which will grant you access to the AWS Console in your
web browser.  The URL can be sent directly to the browser (default), printed
in the terminal or copied into the Copy & Paste buffer of your computer.

Flags:

 * `--duration <minutes>`, `-d` -- AWS Session duration in minutes (default 60)
 * `--arn <arn>` -- ARN of role to assume
 * `--account <account>` -- AWS AccountID of role to assume
 * `--role <role>` -- Name of AWS Role to assume (requires `--account`)

The generated URL is good for 15 minutes after it is created.

The common flag `--url-action` is used both for AWS SSO authentication as well as
what to do with the resulting URL from the `console` command.

### exec

Exec allows you to execute a command with the necessary [AWS environment variables](
https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html).  By default,
if no command is specified, it will start a new interactive shell so you can run multiple
commands.

Flags:

 * `--duration <minutes>`, `-d` -- Override default STS Token duration
 * `--region <region>` -- Override default AWS Region
 * `--arn <arn>` -- Specify ARN of role to assume
 * `--account <account>` -- Specify AccountId for role to assume
 * `--role <role>` -- Specify Role Name to assume (requires `--account`)

Arguments: `[<command>] [<args> ...]`

If `--arn` or both `--account` and `--role` are specified, than
you will skip interactive mode and the command will execute immediately.

The following environment variables are automatically set by `exec`:

 * `AWS_ACCESS_KEY_ID` -- Authentication identifier required by AWS
 * `AWS_SECRET_ACCESS_KEY` -- Authentication secret required by AWS
 * `AWS_SESSION_TOKEN` -- Authentication secret required by AWS
 * `AWS_ACCOUNT_ID` -- The AccountID for your IAM role
 * `AWS_ROLE_NAME` -- The name of the IAM role
 * `AWS_ROLE_ARN` -- The full ARN of the IAM role
 * `AWS_SESSION_EXPIRATION`  -- The date and time when the IAM role credentials will expire
 * `AWS_DEFAULT_REGION` -- Region to use AWS with
 * `AWS_SSO_PROFILE` -- User customizable varible using a template

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

 * `--list-fields` -- List the available fields to print

Arguments: `[<field> ...]`

### flush

Flush any cached AWS SSO/STS credentials.  By default, it only flushes the SSO
credentials used to issue new STS tokens.

Flags:

 * `--all` -- Also delete any non-expired AWS STS credentials from secure store

### renew

Generate a series of `export VARIABLE=VALUE` lines suitable for sourcing into your
shell.  Allows obtaining new AWS credentials when your current session has expired without
starting a new shell.

Suggested use (bash): `eval $(aws-sso renew)`

### tags

Tags dumps a list of AWS SSO roles with the available metadata tags.

Flags:

 * `--account <account>` -- Filter results by AccountId
 * `--role <role>` -- Filter results by Role Name

### Environment Variables

The following environment variables are honored by `exec` and `console`:

 * `AWS_DEFAULT_REGION` -- Region to use AWS with
 * `AWS_SSO_DURATION` -- Default number of minutes to request for session lifetime
 * `AWS_SSO_ROLE_ARN` -- Specify the ARN to assume
 * `AWS_SSO_ACCOUNTID` -- Specify the AWS AccountID for the role to assume
 * `AWS_SSO_ROLE` -- Specify the AWS Role name for the role to assume

## Configuration

By default, `aws-sso` stores it's configuration file in `~/.aws-sso/config.yaml`,
but this can be overridden by setting `$AWS_SSO_CONFIG` in your shell or via the
`--config` flag.

```yaml
SSOConfig:
    <Name of AWS SSO>:
        SSORegion: <AWS Region>
        StartUrl: <URL for AWS SSO Portal>
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

Browser: <path to web browser>
DefaultSSO: <name of AWS SSO>
LogLevel: [error|warn|info|debug|trace]
LogLines: [true|false]
UrlAction: [print|open|clip]
SecureStore: [json|file|keychain|kwallet|pass|secret-service|wincred]
JsonStore: <path to json file>
ProfileFormat: <template>
AccountPrimaryTag: <list of role tags>
PromptColors:
    <Option>: <Color>
```

### Accounts

The `Accounts` block is completely optional!  The only purpose of this block
is to allow you to add additional tags (key/value pairs) to your accounts/roles
to make them easier to select.

By default the following key/values are available as tags to your roles:

 * AccountId
 * AccountName
 * EmailAddress (root account email)
 * RoleName

### Browser / UrlAction

`UrlAction` gives you control over how AWS SSO and AWS Console URLs are opened in a browser:

 * `print` -- Prints the URL in your terminal
 * `open` -- Opens the URL in your default browser or the browser you specified via `--browser` or `Browser`
 * `clip` -- Copies the URL to your clipboard

If `Browser` is not set, then your default browser will be used.  Note that
your browser needs to support Javascript for the AWS SSO user interface.

### DefaultSSO

If you only have a single AWS SSO instance, then it doesn't really matter what you call it,
but if you have two or more, than `Default` is automatically selected unless you manually
specify it here, on the CLI (`--sso`), or via the `AWS_SSO` environment variable.

### LogLevel / LogLines

By default, the `LogLevel` is 'warn'.  You can override it here or via `--log-level` with one
of the following values:

 * error
 * warn
 * info
 * debug
 * trace

`LogLines` includes the file name/line and module name with each log for advanced debugging.

### SecureStore / JsonStore

`SecureStore` supports the following backends:

 * `json` - Cleartext JSON file (insecure and not recommended)  Location can be overridden with `JsonStore`
 * `file` - Encrypted local files (OS agnostic and default)
 * `keychain` - macOS/OSX [Keychain](https://support.apple.com/guide/mac-help/use-keychains-to-store-passwords-mchlf375f392/mac)
 * `kwallet` - [KDE Wallet](https://utils.kde.org/projects/kwalletmanager/)
 * `pass` - [pass](https://www.passwordstore.org)
 * `secret-service` - Freedesktop.org [Secret Service](https://specifications.freedesktop.org/secret-service/latest/re01.html)
 * `wincred` - Windows [Credential Manager](https://support.microsoft.com/en-us/windows/accessing-credential-manager-1b5c916a-6a16-889f-8581-fc16e8165ac0)

### ProfileFormat

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
 * `StringsJoin([]x, y) -- Joins the items in `x` with the string `y`

**Note:** Unlike most values stored in the `config.yaml`, because `ProfileFormat`
values often start with a `{` you will need to quote the value for it to be valid
YAML.

### AccountPrimaryTag

When selecting a role, if you first select by role name (via the `Role` tag) you will
be presented with a list of matching ARNs to select. The `AccountPrimaryTag` automatically
includes another tag name and value as the description to aid in role selection.  By default
the following tags are searched (first match is used):

 * AccountName
 * AccountAlias
 * Email

Set `AccountPrimaryTag` to an empty list to disable this feature.

### PromptColors

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

 * "Black"
 * "DarkRed"
 * "DarkGreen"
 * "Brown"
 * "DarkBlue"
 * "Purple"
 * "Cyan"
 * "LightGrey"

Valid high intensity colors:

 * "DarkGrey"
 * "Red"
 * "Green"
 * "Yellow"
 * "Blue"
 * "Fuchsia"
 * "Turquoise"
 * "White"


## Environment Varables

The following environment variables are honored by `aws-sso`:

 * `AWS_SSO_FILE_PASSPHRASE` -- Passphrase to use with the `file` SecureStore
 * `AWS_DEFAULT_REGION` -- Will pass this value to any new shell created by `exec`
 * `AWS_SSO_CONFIG` -- Specify an alternate path to the `aws-sso` config file
	(default: `~/.aws-sso/config.yaml`)
 * `AWS_SSO_BROWSER` -- Override default browser for AWS SSO login
 * `AWS_SSO` -- Override default AWS SSO instance to use

The `file` SecureStore will use the `AWS_SSO_FILE_PASSPHRASE` environment
variable for the passphrase if it is set. (Not recommended.)

## License

AWS SSO CLI is licnsed under the GPLv3: [License](LICENSE)
