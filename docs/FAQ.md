# Frequently Asked Questions

 * [How do I delete all secrets from the macOS Keychain?](#how-do-i-delete-all-secrets-from-the-macos-keychain)
 * [How good is the Windows support?](#how-good-is-the-windows-support)
 * [Does AWS SSO CLI support Role Chaining?](#does-aws-sso-cli-support-role-chaining)
 * [How does AWS SSO CLI manage the $AWS\_DEFAULT\_REGION?](#how-does-aws-sso-cli-manage-the-aws_default_region)
 * [How to configure ProfileFormat](#how-to-configure-profileformat)


### How do I delete all secrets from the macOS keychain?

 1. Open `/Applications/Utilities/Keychain Access.app`
 2. Choose the `login` keychain
 3. Find the entry named `aws-sso-cli` and right click -> `Delete "aws-sso-cli"`

### How good is the Windows support?

In a word: alpha.

Right now you are pretty much limited to using CommandPrompt (`cmd.exe`) instead
of PowerShell or MINGW64/bash.  Not that you can't use PowerShell or bash, but
there are a number of terminal related issues which cause `aws-sso` to behave
incorrectly.  Would likely have to change how input processing other than for
CLI arguments work for it to work with PowerShell or MINGW64/bash.

[Tracking ticket](https://github.com/synfinatic/aws-sso-cli/issues/189)

There is also the issue right now that the `eval` command does not work on Windows
because it has no equivalant to the bash `eval` and there does not seem to be a
reasonable way to generate and auto-execute batch files.  And of course, batch
files must be written to disk and would contain the clear text secrets that
`aws-sso` works very hard to never write to disk in clear text.

[Tracking ticket](https://github.com/synfinatic/aws-sso-cli/issues/188)

### Does AWS SSO CLI support role chaining?

Yes.  You can use `aws-sso` to assume roles in other AWS accounts or
roles that are not managed via AWS SSO Permission Sets.  For more
information on this, see the [Via](config.md#Via) configuration option.

### How does AWS SSO CLI manage the $AWS\_DEFAULT\_REGION?

AWS SSO will leave the `$AWS_DEFAULT_REGION` environment variable alone
unless the following are all true:

 * The `$AWS_DEFAULT_REGION` is not already defined in your shell
 * You have specified the region in the `config.yaml` via `DefaultRegion`
 * You have not set the `--no-region` flag on the CLI
 * If `$AWS_SSO_DEFAULT_REGION` is set, does it match `$AWS_DEFAULT_REGION?`

If the above are true, then AWS SSO will define both:

 * `$AWS_DEFAULT_REGION`
 * `$AWS_SSO_DEFAULT_REGION`

to the default region as def)ined by `config.yaml`.  If the user changes
roles and the two variables are set to the same region, then AWS SSO will
update the region.   If the user ever overrides the `$AWS_DEFAULT_REGION`
value or deletes the `$AWS_SSO_DEFAULT_REGION` then AWS SSO will no longer
manage the variable.

<!-- https://github.com/synfinatic/aws-sso-cli/issues/166 -->
![](https://user-images.githubusercontent.com/1075352/143502947-1465f68f-0ef5-4de7-a997-ea716facc637.png)

### How to configure ProfileFormat

`aws-sso` uses the `ProfileFormat` configuration option for two different purposes:

 1. Makes it easy to modify your shell `$PROMPT` to include information
	about what AWS Account/Role you have currently assumed by defining the
	`$AWS_SSO_PROFILE` environment variable.
 2. Makes it easy to select a role via the `$AWS_PROFILE` environment variable
	when you use the [config](../README.md#config) command.

By default, `ProfileFormat` is set to `{{ AccountIdStr .AccountId }}:{{ .RoleName }}`
which will generate a value like `02345678901:MyRoleName`.

Some examples:

 * `{{ FirstItem .AccountName .AccountAlias }}` -- If there is an Account Name
	set in the config.yaml print that, otherwise print the Account Alias defined
	by the AWS administrator.
 * `{{ AccountIdStr .AccountId }}` -- Pad the AccountId with leading zeros if it
	is < 12 digits long
 * `{{ .AccountId }}` -- Print the AccountId as a regular number
 * `{{ StringsJoin ":" .AccountAlias .RoleName }} -- Another way of writing
	`{{ .AccountAlias }}:{{ .RoleName }}`
 * `{{ StringReplace " " "_" .AccountAlias }}` -- Replace any spaces (` `) in the
	AccountAlias with an underscore (`_`).
 * `{{ FirstItem .AccountName .AccountAlias | StringReplace " " "_" }}:{{ .RoleName }}` --
	Use the Account Name if set, otherwise use the Account Alias and replace any spaces
	with an underscore and then append a colon, followed by the role name.

For a full list of available variables, [see here](config.md#profileformat).

To see a list of values across your roles for a given variable, you can use
the [list](../README.md#list) command.
