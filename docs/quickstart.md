# AWS SSO CLI Quick Start 

This quick start guide assumes you have already installed AWS SSO CLI. If not,
please read the [install instructions](../README.md#installation).

## Configuration

AWS SSO CLI includes a simple setup wizard to aid in configuration.  This wizard
will automatically run anytime you have a missing `~/.aws-sso/config.yaml` file.

### Multiple AWS SSO Instances?

If you have multiple AWS SSO instances (typically this would be an advanced use-case)
you can edit the `~/.aws-sso/config.yaml` and add the [necessary entries](
config.md#SSOConfig).

If you have multiple AWS SSO instances, then you can modify the default AWS SSO
instance via the [DefaultSSO](config.md#DefaultSSO) option.

## Modify your ~/.aws/config 

The easiest way to use AWS SSO CLI is to integrate it with your `~/.aws/config`
config file.  This allows you to consistently manage which AWS Role to use 
[named profiles](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-profiles.html).

Run: `aws-sso config`

This will add the following lines (example) to your `~/.aws/config` file:

```
# BEGIN_AWS_SSO
[profile Name1]
credential_process = /usr/local/bin/aws-sso process --sso <name> --arn <arn1>
output=json

[profile Name2]
credential_process = /usr/local/bin/aws-sso process --sso <name> --arn <arn2>
output=json
# END_AWS_SSO
```

For more information about this feature, see [the documentation](../README.md#config).

## Using AWS SSO CLI

Once your `~/.aws/config` file has been modified, you can access any AWS SSO role
the same way you would access a traditional role defined via AWS API keys: set the
`AWS_PROFILE` environment variable to the name of the profile.

The only difference is that your API keys are managed via AWS SSO and always safely stored
encrypted on disk!

## Customize Profile Names

By default, each AWS role is given an `$AWS_PROFILE` name matching the
`<AccountID>:<RoleName>`.  You can change this value in one of two ways:

 1. Set the [ProfileFormat](config.md#profileformat) variable to change
	the automatically generated value for each role to a template of your
	choice.
 1. Set the [Profile](config.md#profile) value for the individual role
	to any value you wish.
