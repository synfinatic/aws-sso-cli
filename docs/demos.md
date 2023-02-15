# AWS SSO CLI Demos

### Inital setup via the wizard

Showing how to get started with AWS SSO CLI using the configuration wizard.

<!-- setup -->
[![asciicast](https://asciinema.org/a/462164.svg)](https://asciinema.org/a/462164)

---

### Using the `eval` command

The `eval` command is one way to source the necessary AWS API credentials into your
current shell.

<!-- eval -->
[![asciicast](https://asciinema.org/a/462165.svg)](https://asciinema.org/a/462165)

---

### Using the `config` command and `$AWS_PROFILE`

Do you want to just use the `$AWS_PROFILE` environment variable?  Well, AWS SSO CLI
supports that too!  This demo shows you how to set it up and use it.

<!-- config -->
[![asciicast](https://asciinema.org/a/462163.svg)](https://asciinema.org/a/462163)

---

### Using the `exec` command

The `exec` command supports a powerful tags based approach to selecting the role
to assume and is especially useful if you don't remember the role specifics.

<!-- exec -->
[![asciicast](https://asciinema.org/a/462167.svg)](https://asciinema.org/a/462167)

---

<!-- console -->
### Using the `console` command 

The `console` command allows you to open the AWS Console in your browser for a
given AWS SSO role.  If you have enabled [FirefoxOpenUrlInContainer](
config.md#firefoxopenurlincontainer) then multiple active sessions are possible
as shown here:

![FirefoxContainers Demo](
https://user-images.githubusercontent.com/1075352/166165880-24f7c9af-a037-4e48-aa2d-342f2efe5ad7.gif)
