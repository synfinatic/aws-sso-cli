# Frequently Asked Questions

 * [How do I delete all secrets from the macOS Keychain?](#how-do-i-delete-all-secrets-from-the-macos-keychain)
 * [How good is the Windows support?](#how-good-is-the-windows-support)
 * [How does AWS SSO manage the $AWS\_DEFAULT\_REGION?](#how-does-aws-sso-manage-the-aws_default_region)

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

### How does AWS SSO manage the $AWS\_DEFAULT\_REGION?

AWS SSO will leave the `$AWS_DEFAULT_REGION` environment variable alone
unless the following are all true:

 * The `$AWS_DEFAULT_REGION` is not already defined in your shell
 * You have specified the region in the `config.yaml` via `DefaultRegion`
 * You have not set the `--no-region` flag on the CLI
 * If `$AWS_SSO_DEFAULT_REGION` is set, does it match `$AWS_DEFAULT_REGION?`

If the above are true, then AWS SSO will define both:

 * `$AWS_DEFAULT_REGION`
 * `$AWS_SSO_DEFAULT_REGION`

to the default region as defined by `config.yaml`.  If the user changes
roles and the two variables are set to the same region, then AWS SSO will
update the region.   If the user ever overrides the `$AWS_DEFAULT_REGION`
value or deletes the `$AWS_SSO_DEFAULT_REGION` then AWS SSO will no longer
manage the variable.

<!-- https://github.com/synfinatic/aws-sso-cli/issues/166 -->
![](https://user-images.githubusercontent.com/1075352/143502947-1465f68f-0ef5-4de7-a997-ea716facc637.png)
