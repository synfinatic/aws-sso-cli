# Using ECS Server Mode

## Overview

AWS provides the ability for [ECS Tasks to assume an IAM role](
https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html)
via an HTTP endpoint defined via the `AWS_CONTAINER_CREDENTIALS_FULL_URI` shell
ENV variable.

All AWS SDK clients using the the same ECS Server container credentials endpoint
URL will utilize the same AWS IAM Role.  Note that this feature is also compatible
with the [HTTP Client Provider](
https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/credentials/endpointcreds).

`aws-sso` can emulate this ECS service and allow any process to utilize one or more IAM
roles backed by AWS Identity Center/SSO.

One important distinction between `aws-sso` and this ECS Server, is that the ECS Server
_does not have access to the SecureStore_.  The only SSO or IAM credentials it has
available to it are those you manually load into it's memory.

## Security Considerations

The `aws-sso` ECS Server is intended to run on hosts where a single user has access.
The security of your IAM credentials is dependent on nobody else being able to talk
to the server. Due to a [limitation of the AWS SDK](https://github.com/boto/boto3/issues/4188),
SSL/TLS is not well supported, which means that
[enabling HTTP Authentication](#ecs-server-http-authentication) may not be enough to protect your credentials.

## Starting the ECS Server

The server runs in the foreground to make it easy to start via systemd and Docker.

`aws-sso ecs server`

Will start the server on `localhost:4144`.   For security purposes, the `aws-sso`
ECS Server will default listen on localhost (127.0.0.1) port 4144.  You may select
an alternative IP/port via the `--bind-ip` and `--port` flags.

### Running the ECS Server in the background

The recommended way to run the ECS server in the background is via the
[aws-sso-cli-ecs-server](https://hub.docker.com/repository/docker/synfinatic/aws-sso-cli-ecs-server/general)
Docker image and the `aws-sso ecs docker [start|stop]` commands as this will
automatically configure your SSL key pair and bearer token from the secure store
in the most secure means possible.

**Note:** For security, by default the Docker container will default listen the
host's loopback interface (`127.0.0.1`), but you can enable it listening on
other interfaces using the `--bind-ip` flag.

### ECS Server security

The ECS Server supports both SSL/TLS encryption as well as HTTP Authentication.
Together, they allow using the `aws-sso` ECS Server on multi-user systems in a
secure manner.

**Important:** Failure to configure HTTP Authentication _and_ SSL/TLS encryption
risks any user on the system running the `aws-sso` ECS Server access to your
AWS IAM authentication tokens.

#### ECS Server SSL Certificate

**Important:** Due to a [bug in the AWS SDK](https://github.com/aws/aws-sdk/issues/774)
you can not easily enable SSL at this time.  _I'd greatly
appreciate people to upvote my ticket with AWS and help get it greater
visibility at AWS and hopefully addressed sooner rather than later._

You will need to create an SSL certificate which is _signed by a well trusted CA_
such as DigiCert, Let's Encrypt, Thwate, etc.  Currently, the AWS SDK does _NOT_
support self-signed certificates or private CA's for this endpoint.

<!--
You will need to create an SSL certificate/key pair in PKCS#8/PEM format. Typically,
this will be a self-signed certificate which can be generated thusly:

```bash
$ cat <<-EOF > config.ssl
[dn]
CN=localhost
[req]
distinguished_name = dn
[EXT]
subjectAltName=DNS:localhost,IP:127.0.0.1
keyUsage=digitalSignature
extendedKeyUsage=serverAuth
EOF

$ openssl req -x509 -out localhost.crt -keyout localhost.key \
  -newkey rsa:2048 -nodes -sha256 -subj '/CN=localhost' -extensions EXT -config config.ssl

$ rm config.ssl
```

-->

Once you have your certificate and private key, you will need to save them into the
`aws-sso` secure store:

```bash
aws-sso ecs ssl save --private-key localhost.key --cert-chain localhost.crt
```

**Important:** At this point, you should delete the private key file `localhost.key` for security.

The `localhost.crt` file will be automatically trusted by the `aws-sso` client if it
uses the same secure store so it will be able to validate the server before uploading any IAM
credentials.

If you lose your certificate, you can print it via:

```bash
aws-sso ecs ssl print
```

**Note:** At this time, there is no way to extract the SSL Private Key from the Secure Store.

<!--
#### AWS SDK SSL Limitations

If you create a self-signed certificate as described above, you will not be able to use the
AWS CLI tooling or other AWS SDK's without additional work.  This is because the AWS SDK does
not trust self-signed certificates.  Right now, it is best to get a signed cert by a trusted CA
like Let's Encrypt.  Due to the complexity of this at this time, getting this to work is left
as an exercise to the reader.

-->

##### Using self-signed certificates

In theory, you can add your self-signed certificate or custom CA into the AWS SDK certificate bundle.
However, this file is SDK specific (the Boto3 SDK ships with it's own `cacert.pem` while the Go v2 SDK uses
the system default bundle).  Managing this is not just language specific, but likely to be site-specific
so getting this to work is left as an exercise to the reader.

#### ECS Server HTTP Authentication

The way to configure HTTP Authentication is with a
[bearer token](https://datatracker.ietf.org/doc/html/rfc6750#section-2.1)
as [documented by AWS](https://docs.aws.amazon.com/sdkref/latest/guide/feature-container-credentials.html).

Once you have selected a sufficiently secure secret to use as the bearer token,
you can load it into the Secure Store via:

```bash
aws-sso ecs bearer-token --token '<token>`
```

**Note:** Unlike the `$AWS_CONTAINER_AUTHORIZATION_TOKEN` variable, do not include the
prefix `Bearer ` in the token value.

**Important:** You must choose a strong secret value for your bearer token secret!  This is
what prevents anyone else from using your IAM credentials without your permission.  Your bearer
token should be long and random enough to prevent bruteforce attacks.

## Environment variables

### $AWS\_CONTAINER\_CREDENTIALS\_FULL\_URI

AWS clients and `aws-sso` should use:

`export AWS_CONTAINER_CREDENTIALS_FULL_URI=http://localhost:4144/`

**Note:** If you have configured an SSL certificate as described above, use `https://localhost:4144`.

### $AWS\_CONTAINER\_CREDENTIALS\_RELATIVE\_URI

It is important to _not_ set `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`
as that takes precidence for `AWS_CONTAINER_CREDENTIALS_FULL_URI` and it is not
compatible with `aws-sso`.

### $AWS\_CONTAINER\_AUTHORIZATION\_TOKEN

Specify the HTTP Authentication token used to authenticate communication between the
ECS Server and clients (aws-sso and AWS SDK/CLI).  Should be specified
in the format of `Bearer <auth token value>`.

## Selecting a role via ECS Server

Before you can assume a role, you must select an IAM role for the aws-sso ecs
server to present to clients.

`aws-sso ecs load`

Will start the interactive profile selector.  Or you may specify the `--profile`
flag or the `--account` and `--role` flags to specify the role on the command line.

**Note:** Subsequent calls to `aws-sso ecs load` will alter the current IAM Role
for all AWS Client SDKs using it.

## Assuming a role via ECS Server

Ensure you have exported the following shell ENV variable:

`export AWS_CONTAINER_CREDENTIALS_FULL_URI=http://localhost:4144/`

**Note:** If you have configured an SSL certificate as described above, use `https://localhost:4144/`.

Then just:

`aws sts get-caller-identity`

should show that you are using the IAM Role you loaded into the ecs server process.

## Determining the current role

Since only one role can be loaded at any given time in the default slot, there
may be times you would like to quickly determine the current role without
resorting to an IAM call:

`aws-sso ecs profile`

will return the currently loaded default profile.

## Unloading role credentials

If you would like to remove the default IAM Role credentials:

`aws-sso ecs unload`

## Storing multiple roles at a time

There may be cases where you would like to make multiple roles available at the
same time without running multiple copies of the ECS server via `aws-sso ecs server`.
Each role is stored in a unique named slot based on the `ProfileName` which is
either set via [Profile](config.md#Profile) or the [ProfileFormat](
config.md#ProfileFormat) configuration options.

### Loading

Specify `aws-sso ecs load --slotted ...` and the individual role will be stored in
it's unique named slot based on it's profile name.

### Listing Profiles

To see a list of profiles loaded in named slots use `aws-sso ecs list`.

### Querying

Accessing the individual credentials is done via the `profile` query parameter:

`export AWS_CONTAINER_CREDENTIALS_FULL_URI=http://localhost:4144/slot/ExampleProfileName`

**Note:** If you have configured an SSL certificate as described above, use `httpss://localhost:4144/slot/ExampleProfileName`.

Would utilize the `ExampleProfileName` role.  Note that the `profile` value
value in the URL must be [URL Escaped](https://www.w3schools.com/tags/ref_urlencode.ASP).

### Unloading

To remove a specific IAM Role credential from a named slot in the ECS Server,
you can use:

`aws-sso ecs unload --profile <profile>`

## Errors

The ECS Server API endpoint generates errors with the following JSON format:

```json
{
    "code": "<HTTP error code>",
    "message": "<message>"
}
```

## Authentication

Support for the [$AWS\_CONTAINER\_AUTHORIZATION\_TOKEN](
https://docs.aws.amazon.com/sdkref/latest/guide/feature-container-credentials.html) environment
variable is supported.

## HTTPS Transport

HTTPS support is a work in progress.  Right now, due to a [limitation with the AWS SDK](
https://github.com/aws/aws-sdk/issues/774) only SSL certificates signed by CA that the
AWS SDK trusts will work. If you think this feature would be useful to you, please leave
a comment so AWS knows they should prioritize this work.
