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

## Starting the ECS Server

The server runs in the foreground to make it easy to start via systemd and Docker.

`aws-sso ecs run`

Will start the service on `localhost:4144`.   For security purposes, the `aws-sso`
ECS Server will _only_ run on localhost/127.0.0.1.  You may select an alternative
port via the `--port` flag or setting the `AWS_SSO_ECS_PORT` environment variable.

### Running the ECS Server in the background

The recommended way to run the ECS server in the background is via the
[aws-sso-cli-ecs-server](https://hub.docker.com/repository/docker/synfinatic/xb8-docsis-stats/general)
Docker image and the `aws-sso ecs docker [start|stop]` commands as this will
automatically configure your SSL key pair and bearer token from the secure store
in the most secure means possible.

**Note:** By default for security, the Docker container will only listen the
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

**Important:** Due to a [bug in the AWS Boto3 SDK](https://github.com/synfinatic/aws-sso-cli/issues/936)
you can not enable SSL at this time.  I'm currently unsure if other AWS SDKs
(like the Go SDK used by Terraform) also experience this issue.  __I'd greatly
appreciate people to upvote my ticket with AWS and help get it greater
visibility at AWS and hopefully addressed sooner rather than later.__

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

Once you have your certificate and private key, you will need to save them into the
`aws-sso` secure store:

```bash
$ aws-sso ecs cert load --private-key localhost.key --cert-chain localhost.crt
```

**Important:** At this point, you should delete the private key file `localhost.key` for security.

The `localhost.crt` file will be automatically trusted by the `aws-sso` client if it
uses the same secure store so it will be able to validate the server before uploading any IAM
credentials.

If you lose your certificate, you can print it via:

```bash
$ aws-sso ecs cert print
```

**Note:** At this time, there is no way to extract the SSL Private Key from the Secure Store.

#### AWS SDK SSL Limitations

If you create a self-signed certificate as described above, you will not be able to use the
AWS CLI tooling or other AWS SDK's without additional work.  This is because the AWS SDK does
not trust self-signed certificates.  Right now, it is best to get a signed cert by a trusted CA
like Let's Encrypt.  Due to the complexity of this at this time, getting this to work is left
as an exercise to the reader.

#### ECS Server HTTP Authentication

The way to configure HTTP Authentication is with a
[bearer token](https://datatracker.ietf.org/doc/html/rfc6750#section-2.1)
as [documented by AWS](https://docs.aws.amazon.com/sdkref/latest/guide/feature-container-credentials.html).

Once you have selected a sufficiently secure secret to use as the bearer token,
you can load it into the Secure Store via:

```bash
aws-sso ecs bearer-token --token '<token>`
```

**Important:** You must choose a strong secret value for your bearer token secret!  This is
what prevents anyone else from using your IAM credentials without your permission.  Your bearer
token should be long and random enough to prevent bruteforce attacks.

## Environment variables

### AWS\_CONTAINER\_CREDENTIALS\_FULL\_URI

AWS clients and `aws-sso` should use:

`AWS_CONTAINER_CREDENTIALS_FULL_URI=http://localhost:4144/`

**Note:** If you have configured an SSL certificate as described above, use `https://localhost:4144`.

### AWS\_CONTAINER\_CREDENTIALS\_RELATIVE\_URI

It is important to _not_ set `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`
as that takes precidence for `AWS_CONTAINER_CREDENTIALS_FULL_URI` and it is not
compatible with `aws-sso`.

### AWS\_CONTAINER\_AUTHORIZATION\_TOKEN

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

`export AWS_CONTAINER_CREDENTIALS_FULL_URI=http://localhost:4144/creds`

**Note:** If you have configured an SSL certificate as described above, use `https://localhost:4144/creds`.

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
same time without running multiple copies of the ECS server via `aws-sso ecs run`.
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

Support for the [AWS\_CONTAINER\_AUTHORIZATION\_TOKEN](
https://docs.aws.amazon.com/sdkref/latest/guide/feature-container-credentials.html) environment
variable is supported.

## HTTPS Transport

Support for using [HTTPS](https://github.com/synfinatic/aws-sso-cli/issues/518)
is TBD.  Please vote for this feature if you want it!
