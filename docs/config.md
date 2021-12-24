# Configuration

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
                        Via: <Previous Role>  # optional, for role chaining

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
HistoryMinutes: <integer>
ListFields:
    - <field 1>
    - <field 2>
    - <field N>
```

## SSOConfig

This is the top level block for your AWS SSO instances.  Typically an organization
will have a single AWS SSO instance for all of their accounts under a single AWS master
payer account.  If you have more than one AWS SSO instance, then `Default` will be
the default unless overridden with `DefaultSSO`.

The `SSOConfig` config block is required.

### StartUrl

Each AWS SSO instance has a unique start URL hosted by AWS for interacting with your
SSO provider (Okta/OneLogin/etc).  Should be in the format of `https://xxxxxxx.awsapps.com/start`.

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

#### Name

Alternate name of the account.  Shown as `AccountName` for the list command.
Not to be confused with the `AccountAlias` which is defined by the account owner
in AWS.

#### Tags

List of key / value pairs, used by `aws-sso` in prompt mode.  Any tag placed at
the account level will be applied to all roles in that account.

#### Roles

The `Roles` block is optional, except for roles you which to assume via role chaining.

##### Tags

List of key / value pairs, used by `aws-sso` in prompt mode.  Any tag placed at
the role level will be applied to only that role.

##### Via

Impliments the concept of [role chaining](
https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_terms-and-concepts.html).

`Via` defines which role to assume before calling [sts:AssumeRole](
https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html) in order
to switch to the specified role.  This allows you to define and assume roles in AWS
accounts that are not included in your organization's AWS SSO scope or roles that
were not defined via an [AWS SSO Permission Set](
https://docs.aws.amazon.com/singlesignon/latest/userguide/permissionsetsconcept.html).

## Browser / UrlAction

`UrlAction` gives you control over how AWS SSO and AWS Console URLs are opened in a browser:

 * `print` -- Prints the URL in your terminal
 * `open` -- Opens the URL in your default browser or the browser you specified via `--browser` or `Browser`
 * `clip` -- Copies the URL to your clipboard

If `Browser` is not set, then your default browser will be used.  Note that
your browser needs to support Javascript for the AWS SSO user interface.

## DefaultSSO

If you only have a single AWS SSO instance, then it doesn't really matter what you call it,
but if you have two or more, than `Default` is automatically selected unless you manually
specify it here, on the CLI (`--sso`), or via the `AWS_SSO` environment variable.

## LogLevel / LogLines

By default, the `LogLevel` is 'warn'.  You can override it here or via `--log-level` with one
of the following values:

 * `error`
 * `warn`
 * `info`
 * `debug`
 * `trace`

`LogLines` includes the file name/line and module name with each log for advanced debugging.

## ConsoleDuration

By default, the `console` command opens AWS Console sessions which are valid for 60 minutes.
If you wish to override the default session duration, you can specify the number of minutes here
or with the `--duration` flag.

## SecureStore / JsonStore

`SecureStore` supports the following backends:

 * `file` - Encrypted local files (OS agnostic and default)
 * `keychain` - macOS [Keychain](https://support.apple.com/guide/mac-help/use-keychains-to-store-passwords-mchlf375f392/mac)
 * `kwallet` - [KDE Wallet](https://utils.kde.org/projects/kwalletmanager/)
 * `pass` - [pass](https://www.passwordstore.org)
 * `secret-service` - Freedesktop.org [Secret Service](https://specifications.freedesktop.org/secret-service/latest/re01.html)
 * `wincred` - Windows [Credential Manager](https://support.microsoft.com/en-us/windows/accessing-credential-manager-1b5c916a-6a16-889f-8581-fc16e8165ac0)
 * `json` - Cleartext JSON file (very insecure and not recommended).  Location can be overridden with `JsonStore`

## ProfileFormat

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

## AccountPrimaryTag

When selecting a role, if you first select by role name (via the `Role` tag) you will
be presented with a list of matching ARNs to select. The `AccountPrimaryTag` automatically
includes another tag name and value as the description to aid in role selection.  By default
the following tags are searched (first match is used):

 * `AccountName`
 * `AccountAlias`
 * `Email`

Set `AccountPrimaryTag` to an empty list to disable this feature.

## PromptColors

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

## HistoryLimit

Limits the number of recently used roles tracked via the History tag.
Default is last 10 unique roles.  Set to 0 to disable.

## HistoryMinutes

Limits the list of recently used roles tracked via the History tag to
roles that were last used within the last X minutes.  Set to 0 to not limit
based on the time.  Default is 1440 minutes (24 hours).

This option has no effect if `HistoryLimit` is set to 0.

## ListFields

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
