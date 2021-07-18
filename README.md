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
`~/.aws/config` for each and every role you wish to assume which can be
difficult to manage and use.

Instead, it focuses on making it easy to select a role via CLI arguments or
via an interactive auto-complete experience with automatic and user-defined
metadata (tags) and exports the necessary [AWS STS Token credentials](
https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_use-resources.html#using-temp-creds-sdk-cli)
to your shell environment.

[![asciicast](https://asciinema.org/a/UOZHKrsUSBXDeP5BS361UcmDU.svg)](https://asciinema.org/a/UOZHKrsUSBXDeP5BS361UcmDU)

## Security

Unlike the official [AWS cli tooling](https://aws.amazon.com/cli/), _all_
authentication tokens and credentials used for accessing AWS and your SSO
provider are encrypted on disk using your choice of secure storage solution.

Credentials encrypted by `aws-sso` and not via the standard AWS CLI tool:

 * AWS SSO ClientID/ClientSecret -- `~/.aws/sso/cache/botocore-client-id-<region>.json`
 * AWS SSO AccessToken -- `~/.aws/sso/cache/<random>.json`
 * AWS Profile Access Credentials -- `~/.aws/cli/cache/<random>.json`

As you can see, not only does the standard AWS CLI tool expose the temporary
AWS access credentials to your IAM roles, but more importantly the SSO
AccessToken which can be used to fetch IAM credentials for any role you have
been granted access!

## Installation

 * Option 1: [Download binary](https://github.com/synfinatic/aws-sso-cli/releases)
 * Option 2: Build from source:
	1. Install [GoLang](https://golang.org) and GNU Make
	1. Clone this repo
	1. Run `make` (or `gmake`)
	1. Your binary will be created in the `dist` directory

In both cases, copy the binary to a reasonable location (such as `/usr/local/bin`) and
ensure that it is executable (`chmod 755 <path>`).

## Commands

 * `exec` -- Exec a command with a selected role
 * `list` -- List all accounts & roles
 * `expire` -- Force expire of AWS SSO credentials
 * `tags` -- List manually created tags for each role
 * `version` -- Print the version of aws-sso

### Common Flags

 * `--help`, `-h` -- Builtin and context sensitive help
 * `--level <level>`, `-L` -- Change default log level: [error|warn|info|debug]
 * `--lines` -- Print file number with logs
 * `--config <file>`, `-c` -- Specify alternative config file
 * `--browser <path>`, `-b` -- Override default browser to open AWS SSO URL
 * `--url`, `-u` -- Print URL instead of opening in browser
 * `--sso <name>`, `-S` -- Specify non-default AWS SSO instance to use

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

The following environment variables are honored by `exec`:

 * `AWS_DEFAULT_REGION` -- Region to use AWS with
 * `AWS_SSO_DURATION` -- Default number of minutes to request for session lifetime
 * `AWS_SSO_ROLE_ARN` -- Specify the ARN to assume
 * `AWS_SSO_ACCOUNTID` -- Specify the AWS AccountID for the role to assume
 * `AWS_SSO_ROLE` -- Specify the AWS Role name for the role to assume

The following environment variables are automatically set by `exec`:

 * `AWS_ACCESS_KEY_ID` -- Authentication identifier required by AWS
 * `AWS_SECRET_ACCESS_KEY` -- Authentication secret required by AWS
 * `AWS_SESSION_TOKEN` -- Authentication secret required by AWS
 * `AWS_ACCOUNT_ID` -- The AccountID for your IAM role
 * `AWS_ROLE_NAME` -- The name of the IAM role
 * `AWS_ROLE_ARN` -- The full ARN of the IAM role
 * `AWS_SESSION_EXPIRATION`  -- The date and time when the IAM role credentials will expire
 * `AWS_DEFAULT_REGION` -- Region to use AWS with

### list

List will list all of the AWS Roles you can assume with the metadata/tags available
to be used for interactive selection with `exec`.  You can control which fields are
printed by specifying the field names as arguments.

Flags:

 * `--list-fields` -- List the available fields to print
 * `--force-update` -- Force updating of the cache of roles available via AWS SSO

Arguments: `[<field> ...]`

### flush

Flush any cached AWS SSO credentials.  By default, it only deletes the temorary
Client Token which represents your AWS SSO session for the specified AWS SSO portal.

### tags

Tags dumps a list of AWS SSO roles with the available metadata tags.

Flags:

 * `--account <account>` -- Filter results by AccountId
 * `--role <role>` -- Filter results by Role Name

## Configuration

By default, `aws-sso` stores it's configuration file in `~/.aws-sso/config.yaml`,
but this can be overridden by setting `$AWS_SSO_CONFIG` in your shell or via the
`--config` flag.

```
SSOConfig:
    <Name of AWS SSO>:  # `Default` defines the automatically selected AWS SSO instance
        SSORegion: <AWS Region>
        StartUrl: <URL for AWS SSO Portal>
        Duration: <minutes>  # Set default duration time
        Accounts:  # optional block
            <AccountId>:  # account config is optional
                Name: <Friendly Name of Account>
                Tags:  # tags for the account
                    <Key1>: <Value1>
                    <Key2>: <Value2>
                Roles:
                    - ARN: <ARN of Role>
                      Tags:  # tags specific for this role
                          <Key1>: <Value1>
                          <Key2>: <Value2>
                      Duration: 120  # override default duration time in minutes

Browser: <override path to browser>
PrintUrl: [false|true]  # print URL instead of opening it in the browser
SecureStore: [json|file|keychain|kwallet|pass|secret-service|wincred]
JsonStore: <path to json file>
```

If `Browser` is not set, then your default browser will be used.  Note that
your browser needs to support Javascript for the AWS SSO user interface.

`SecureStore` supports the following backends:

 * `json` - Cleartext JSON file (insecure and not recommended)
 * `file` - Encrypted local files (OS agnostic and default)
 * `keychain` - macOS/OSX [Keychain](https://support.apple.com/guide/mac-help/use-keychains-to-store-passwords-mchlf375f392/mac)
 * `kwallet` - [KDE Wallet](https://utils.kde.org/projects/kwalletmanager/)
 * `pass` - [pass](https://www.passwordstore.org)
 * `secret-service` - Freedesktop.org [Secret Service](https://specifications.freedesktop.org/secret-service/latest/re01.html)
 * `wincred` - Windows [Credential Manager](https://support.microsoft.com/en-us/windows/accessing-credential-manager-1b5c916a-6a16-889f-8581-fc16e8165ac0)

The `Accounts` block is completely optional!  The only purpose of this block
is to allow you to add additional tags (key/value pairs) to your accounts/roles
to make them easier to select.

By default the following key/values are available as tags:

 * AccountId
 * AccountName
 * EmailAddress (root account email)
 * RoleName

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
