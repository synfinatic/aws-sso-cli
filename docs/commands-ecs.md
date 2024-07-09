# ECS Commands

For information about the ECS Server functionality, see the [ecs-server](ecs-server.md) page.

## Commands

### ecs auth

Configures the HTTP Authentication BearerToken.  Once set, all future client
requests to the ECS Server will need to provide the correct credentials.  
`aws-sso` utilizing the same SecureStore as the ECS Server will automatically
provide the necessary HTTP Auth header, but other AWS clients utilizing the
AWS SDK will require [$AWS_CONTAINER_AUTHORIZATION_TOKEN](
https://docs.aws.amazon.com/sdkref/latest/guide/feature-container-credentials.html) to be set.

Flags:

 * `--bearer-token` -- Specify the bearer token secret.
 * `--delete` -- Delete the bearer token and disable authentication.

---

### ecs ssl save

 Configures the SSL Certificate and Private Key to enable SSL/TLS.  Saves the
 SSL certificate and private key to the SecureStore.

 **Note:** At this time, this feature is not recommended due to a bug
 in the [AWS SDK](https://github.com/boto/boto3/issues/4188).

 Flags:

  * `--certificate` -- Path to SSL certificate file in PEM format
  * `--private-key` -- Path to SSL private key in PEM format

---

### ecs ssl delete

Delete the SSL certificate and private key from the Secure Store and disables
SSL/TLS for the ECS Server.

---

### ecs ssl print

Prints the SSL public certificate stored in the SecureStore.

---

### ecs server

Starts the ECS Server in the foreground.

Flags:

 * `--disable-auth` -- Disables HTTP Authentication, even if a Bearer Token is available
 * `--disable-ssl` -- Disables SSL/TLS, even if a certificate and private key are available

---

### ecs docker start

Starts the ECS Server in a Docker container.

Flags:

  * `--disable-ssl` -- Disables SSL/TLS, even if a certificate and private key are available.
  * `--bind-ip` -- IP address to bind the service to.  (default 127.0.0.1)
  * `--port` -- Port to listen on.  (default 4144)
  * `--version` -- Version of the `synfinatic/aws-sso-cli-ecs-server` docker image to use

---

### ecs docker stop

Stops the ECS Server Docker container.

---

### ecs list

List the AWS Profiles stored in the ECS Server.

Flags:

 * `--server` -- host:port of the ECS Server (default `localhost:4144`)

---

### ecs load

Load the AWS IAM Role credentials into the ECS Server for clients to use.

Flags:

 * `--arn <arn>`, `-a` -- ARN of role to assume (`$AWS_SSO_ROLE_ARN`)
 * `--account <account>`, `-A` -- AWS AccountID of role to assume (`$AWS_SSO_ACCOUNT_ID`)
 * `--role <role>`, `-R` -- Name of AWS Role to assume (requires `--account`) (`$AWS_SSO_ROLE_NAME`)
 * `--profile <profile>`, `-p` -- Name of AWS Profile to assume
 * `--server` -- host:port of the ECS Server (default `localhost:4144`)
 * `--slotted` -- Load the IAM credentials into a unique slot using the ProfileName as the key

You can provide `--profile` or `--arn` or (`--account` and `--role`) to specify the IAM role to load.

If you do not specify `--slotted`, the role will be loaded into the default URL path at `/`.  If you
would like to load multiple roles, specify `--slotted` and the role will be loaded into `/slot/<profile name>`

---

### ecs unload

Removes the AWS IAM Role credentials from the ECS Server and makes them unavailable to any clients to use.

Flags:

 * `--profile <profile>`, `-p` -- Slot of AWS Profile to unload
 * `--server` -- host:port of the ECS Server (default `localhost:4144`)

By default, this will unload the IAM credentials for the default role.  Passing in
`--profile <profile name>` will unload the credentials in the named slot.

---

### ecs profile

Fetches the ProfileName of the role stored in the default slot of the ECS Server.

Flags:

 * `--slotted` -- Load the IAM credentials into a unique slot using the ProfileName as the key