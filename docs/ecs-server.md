# Using ECS Server Mode

 * [Overview](#overview)
 * [Starting the ECS Server](#starting-the-ecs-server)
 * [Environment variables](#environment-variables)
   * [AWS\_CONTAINER\_CREDENTIALS\_FULL\_URI](#aws-container-credentials-full-uri)
 * [Selecing a role via ECS Server](#selecting-a-role-via-ecs-server)
 * [Assuming a role via ECS Server](#assuming-a-role-via-ecs-server)

## Overview

AWS provides the ability for [ECS Tasks to assume an IAM role](
https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html)
via an HTTP endpoint defined via the `AWS_CONTAINER_CREDENTIALS_FULL_URI` shell ENV variable.

All AWS SDK clients using the the same ECS Server container credentials endpoint
will utilize the same AWS IAM Role.

## Starting the ECS Server

The server runs in the foreground to make it easy to start via systemd and Docker.

`aws-sso ecs run --port 8444`

Will start the service on `localhost:8444`.  

## Environment variables

### AWS\_CONTAINER\_CREDENTIALS\_FULL\_URI

AWS clients and `aws-sso` should use:

`AWS_CONTAINER_CREDENTIALS_FULL_URI=http://localhost:8444/get-credentials`

**Note:** It is important to _not_ set `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` as that
takes precidence for `AWS_CONTAINER_CREDENTIALS_FULL_URI`.

## Selecting a role via ECS Server

Before you can assume a role, you must select an IAM role for the aws-sso ecs server to
present to clients.

```bash 
AWS_CONTAINER_CREDENTIALS_FULL_URI=http://localhost:8444/get-credentials aws-sso ecs load ...
```

**Note:** Subsequent calls to `aws-sso ecs load ...` will alter the current IAM Role
for all AWS Client SDKs using it.

## Assuming a role via ECS Server

Ensure you have exported the following shell ENV variable:

`export AWS_CONTAINER_CREDENTIALS_FULL_URI=http://localhost:8444/get-credentials`

Then just:

`aws sts get-caller-identity`

should show that you are using the IAM Role you loaded into the ecs server process.
