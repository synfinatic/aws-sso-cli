# Setup Wizard

First time users are greeted by the `aws-sso setup wizard`:

## AWS Partition

Amazon Web Services is comprised of multiple partitions which are (for the most part) completely
separated from each other:

* Commercial -- (choose this if you don't know)
* US GovCloud -- aka FedRAMP
* China
* EU Digital Sovereignty (Brandenberg, Germany)

## SSO Start URL

This is the URL your administrator [should have given you](
https://docs.aws.amazon.com/signin/latest/userguide/sign-in-urls-defined.html#access-portal-url).
Most likely this is of the format of `https://d-XXXXXXXXXX.awsapps.com/start` or
`https://<subdomain>.awsapps.com/start` but the domain name will depend on the partition.

## AWS SSO Region

This is the AWS Region that the AWS SSO / Identity Center is located in.
The options available to you is determined by the partition you selected
above.

## Profile Format

This is the default template used to generate the `AWS_PROFILE` values
for your roles.  See [Config:ProfileFormat](config.md#profileformat) for
more information.

* Default: `{{ .AccountIdPad }}:{{ .RoleName }}`
* Friendly: `{{ FirstItem .AccountName (.AccountAlias | nospace) }}:{{ .RoleName }}`

## Advanced (Optional)

You can re-run through the configuration wizard at any time by running
`aws-sso setup wizard`.  By default, this only does a very basic setup; for a more
advanced setup (more questions), use `aws-sso setup wizard --advanced`.
