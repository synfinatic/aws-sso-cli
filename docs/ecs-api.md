# ECS Server REST API

If you have [defined a bearer token](ecs-commands.md#ecs-auth) then all REST calls
must define the necesary HTTP Authentication header.

If you have [enabled SSL](ecs-commands.md#ecs-ssl-save) then all REST calls must
be over SSL/TLS.

## Default slot AWS IAM Role credentials

### GET /

Fetch the default IAM credentials.

Reply:

```json
{
    "AccessKeyId": "ASI....",
    "SecretAccessKeyId": "<Secret Access Key ID>",
    "Token": "<Temprorary security token>",
    "Expiration": "<Date in RFC3339 / ISO8601 format>",
    "RoleArn": "<ARN of the role>",
}
```

### GET /profile

Fetch the profile name of the default credentials.

Reply:

```json
{
    "ProfileName": "<aws-sso profile name>",
    "AccountId": "<AWS Account ID>",
    "RoleName": "<IAM Role name>",
    "Expiration": <Unix epoch seconds>,
    "Expires": "<how long until expires string>"
}
```

### PUT /

Upload default credentials.

Request:

```json
{
    "ProfileName": "<aws-sso profile name",
    "Creds": {
        "accountId": "<AWS AccountID of the role>",
        "roleName": "<Name of the role>",
        "accessKeyId": "ASI....",
        "secretAccessKey": "<secret access key id value>",
        "sessionToken": "<temprorary security token>",
        "expiration": "expiration Epoch in milliseconds"
    }
}
```

Reply:

```json
{
    "code": "<HTTP error code>",
    "message": "<message>"
}
```

### DELETE /

Delete default credentials.

```json
{
    "code": "<HTTP error code>",
    "message": "<message>"
}
```

## Slotted credentials

### GET /slot

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

### GET /slot/&lt;profile&gt;

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

### PUT /slot/&lt;profile&gt;

Upload credentials of the named profile.

Request:

```json
{
    "ProfileName": "<aws-sso profile name",
    "Creds": {
        "accountId": "<AWS AccountID of the role>",
        "roleName": "<Name of the role>",
        "accessKeyId": "ASI....",
        "secretAccessKey": "<secret access key id value>",
        "sessionToken": "<temprorary security token>",
        "expiration": "expiration Epoch in milliseconds"
    }
}
```

Reply:

```json
{
    "code": "<HTTP error code>",
    "message": "<message>"
}
```

### DELETE /slot/&lt;profile&gt;

Delete credentials of the named profile.

```json
{
    "code": "<HTTP error code>",
    "message": "<message>"
}
```

### DELETE /slot

Delete all named credentials.

```json
{
    "code": "<HTTP error code>",
    "message": "<message>"
}
```

## Healthcheck

Healthcheck routes do **not** require authentication, making them suitable for use as
Kubernetes liveness/readiness probes or Docker Compose `healthcheck:` commands.

### GET /healthcheck

Returns whether the default credential slot has valid (non-expired) credentials loaded.

Success reply (`200 OK`):

```json
{
    "status": "ok",
    "profile": "<aws-sso profile name>",
    "expires": "<date in RFC3339 / ISO8601 format>"
}
```

Failure reply (`503 Service Unavailable`) when no credentials are loaded:

```json
{"status": "no credentials loaded"}
```

Failure reply (`503 Service Unavailable`) when credentials are expired:

```json
{"status": "credentials expired"}
```

### GET /healthcheck/slot/&lt;profile&gt;

Returns whether the named credential slot has valid (non-expired) credentials loaded.

Success reply (`200 OK`):

```json
{
    "status": "ok",
    "profile": "<aws-sso profile name>",
    "expires": "<date in RFC3339 / ISO8601 format>"
}
```

Failure reply (`503 Service Unavailable`) when the slot is not found or credentials are expired:

```json
{"status": "slot not found"}
```

```json
{"status": "credentials expired"}
```
