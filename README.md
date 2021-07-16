# AWS SSO CLI

## About

AWS SSO CLI is a replacement for using the [aws configure sso](
https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html)
wizard with a focus on security and ease of use for organizations with
many AWS Accounts and/or users with many Roles to assume.

## What does AWS SSO CLI do?

AWS SSO CLI makes it easy to manage your shell environment variables allowing
you to access the AWS API using CLI tools.  Unlike the official AWS tooling,
`aws-sso` does not require defining named profiles in your `~/.aws/config`
for each and every role you wish to assume which can be difficult to manage
and use.

Instead, it focuses on making it easy to select a role via CLI arguments or
via an interactive auto-complete experience with automatic and user-defined
metadata (tags) and exports the necessary [AWS STS Token credentials](
https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_use-resources.html#using-temp-creds-sdk-cli)
to your shell environment.

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
PrintUrl: [false|true]  # print URL instead of opening it in default browser
SecureStore: [json|file|keychain|kwallet|pass|secret-service|wincred]
JsonStore: <path to json file>
```

SecureStore supports the following backends:

 * `json` - Cleartext JSON file (insecure and not recommended)
 * `file` - Encrypted local files (OS agnostic and default)
 * `keychain` - macOS/OSX [Keychain](https://support.apple.com/guide/mac-help/use-keychains-to-store-passwords-mchlf375f392/mac)
 * `kwallet` - [KDE Wallet](https://utils.kde.org/projects/kwalletmanager/)
 * `pass` - [pass](https://www.passwordstore.org)
 * `secret-service` - Freedesktop.org [Secret Service](https://specifications.freedesktop.org/secret-service/latest/re01.html)
 * `wincred` - Windows [Credential Manager](https://support.microsoft.com/en-us/windows/accessing-credential-manager-1b5c916a-6a16-889f-8581-fc16e8165ac0)

## License

AWS SSO CLI is licnsed under the GPLv3: [License](LICENSE)
