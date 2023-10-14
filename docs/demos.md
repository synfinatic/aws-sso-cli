# AWS SSO CLI Demos

### Inital setup via the wizard

Showing how to get started with AWS SSO CLI using the configuration wizard and how
to use the `exec` command to select a role via the powerful interactive interface.

<!-- setup -->
[![asciicast](https://asciinema.org/a/614407.svg)](https://asciinema.org/a/614407)

---

### Using the `aws-sso-profile` command

The `aws-sso-profile` shell integration is the easiest way to source the
necessary AWS API credentials into your current shell.

<!-- profile -->
[![asciicast](https://asciinema.org/a/614412.svg)](https://asciinema.org/a/614412)

---

### Using the `config-profiles` command and `$AWS_PROFILE`

Do you want to just use the `$AWS_PROFILE` environment variable?  Well, AWS SSO CLI
supports that too!  This demo shows you how to set it up and use it.

<!-- config-profiles -->
[![asciicast](https://asciinema.org/a/614413.svg)](https://asciinema.org/a/614413)

---

<!-- console -->
### Using the `console` command

The `console` command allows you to open the AWS Console in your browser for a
given AWS SSO role.  If you have enabled [FirefoxOpenUrlInContainer](
config.md#firefoxopenurlincontainer) then multiple active sessions are possible
as shown here:

![FirefoxContainers Demo](
https://user-images.githubusercontent.com/1075352/166165880-24f7c9af-a037-4e48-aa2d-342f2efe5ad7.gif)
