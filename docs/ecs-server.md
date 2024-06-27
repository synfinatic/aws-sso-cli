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

## Environment variables

### AWS\_CONTAINER\_CREDENTIALS\_FULL\_URI

AWS clients and `aws-sso` should use:

`AWS_CONTAINER_CREDENTIALS_FULL_URI=http://localhost:4144/`

### AWS\_CONTAINER\_CREDENTIALS\_RELATIVE\_URI

It is important to _not_ set `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`
as that takes precidence for `AWS_CONTAINER_CREDENTIALS_FULL_URI` and it is not
compatible with `aws-sso`.

### AWS\_CONTAINER\_AUTHORIZATION\_TOKEN

Specify the HTTP Authentication token used to authenticate communication between the
ECS Server and clients (aws-sso and AWS SDK/CLI).  Typically the value should be specified
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

## REST API

### Default credentials

#### GET /

Fetch default credentials.

```json
{
    "AccessKeyId": "ASI....",
    "SecretAccessKeyId": "<Secret Access Key ID>",
    "Token": "<Temprorary security token>",
    "Expiration": "<Date in RFC3339 / ISO8601 format>",
    "RoleArn": "<ARN of the role>",
}
```

#### GET /profile

Fetch profile name of the default credentials.

```json
{
    "ProfileName": "<aws-sso profile name>",
    "AccountId": "<AWS Account ID>",
    "RoleName": "<IAM Role name>",
    "Expiration": <Unix epoch seconds>,
    "Expires": "<how long until expires string>"
}
```

#### PUT /

Upload default credentials.

```json
{
    "code": "<HTTP error code>",
    "message": "<message>"
}
```

#### DELETE /

Delete default credentials.

```json
{
    "code": "<HTTP error code>",
    "message": "<message>"
}
```

### Slotted credentials

#### GET /slot

Fetch list of default credentials.

```json
[
    {
        "ProfileName": "<profile name>",
        "AccountId": "<AWS Account ID>",
        "RoleName": "<IAM Role Name>",
        "Expiration": <Unix Epoch Seconds>,
        "Expires": "<how long until expires string>"
    },
    <more entries...>
]
```

#### GET /slot/&lt;profile&gt;

Fetch credentials of the named profile.

```json
{
    "AccessKeyId": "ASI....",
    "SecretAccessKeyId": "<secret access key id value>",
    "Token": "<temprorary security token>",
    "Expiration": "<date in RFC3339 / ISO8601 format>",
    "RoleArn": "<ARN of the role>",
}
```

#### PUT /slot/&lt;profile&gt;

Upload credentials of the named profile.

```json
{
    "code": "<HTTP error code>",
    "message": "<message>"
}
```

#### DELETE /slot/&lt;profile&gt;

Delete credentials of the named profile.

```json
{
    "code": "<HTTP error code>",
    "message": "<message>"
}
```

#### DELETE /slot

Delete all named credentials.

```json
{
    "code": "<HTTP error code>",
    "message": "<message>"
}
```
