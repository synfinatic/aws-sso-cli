# ECS Server with Docker Compose Example

This is a basic example shows how to run the ECS credential server alongside your own
application container, then load AWS credentials into the server using
`aws-sso ecs load`.   Note that this example does not include any support for
authentication or encryption via ([aws-sso setup ecs](commands.md#setup-ecs)).

## Sample docker-compose.yaml

```yaml
services:
 aws-sso-cli-ecs-server:
  image: synfinatic/aws-sso-cli-ecs-server:latest
  container_name: aws-sso-cli-ecs-server
  ports:
    - "127.0.0.1:4144:4144"
  volumes:
    - type: bind
      source: $HOME/.aws-sso/mnt
      target: /app/.aws-sso/mnt
      read_only: false

 app:
  image: yourorg/your-custom-service:latest
  build: .
  container_name: custom-service
  depends_on:
    - aws-sso-cli-ecs-server
  environment:
    AWS_CONTAINER_CREDENTIALS_FULL_URI: http://aws-sso-cli-ecs-server:4144/
```

## Sample start-stop.sh

```bash
#!/usr/bin/env bash
set -euo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yaml}"

usage() {
  cat <<'EOF'
Usage:
  ./start-stop.sh start <aws-profile>
  ./start-stop.sh stop

Or set AWS_PROFILE and run:
  AWS_PROFILE=<aws-profile> ./start-stop.sh start
EOF
}

start() {
  if [[ -z "${PROFILE}" && $# -lt 1 ]]; then
    echo "ERROR: missing AWS profile"
    usage
    exit 1
  fi

  local selected_profile="${PROFILE}"
  if [[ -z "${selected_profile}" ]]; then
    selected_profile="$1"
  fi

  echo "Starting services..."
  docker compose -f "${COMPOSE_FILE}" up -d

  echo "Loading profile '${selected_profile}' into ECS server..."
  aws-sso ecs load --server localhost:4144 --profile "${selected_profile}"

  echo "Done. Containers are up and credentials are loaded."
}

stop() {
  echo "Stopping services..."
  docker compose -f "${COMPOSE_FILE}" down
}

main() {
  if [[ $# -lt 1 ]]; then
    usage
    exit 1
  fi

  case "$1" in
    start)
      shift
      start "$@"
      ;;
    stop)
      stop
      ;;
    *)
      usage
      exit 1
      ;;
  esac
}

main "$@"
```

Make it executable:

```bash
chmod +x start-stop.sh
```

## Usage

Start and load profile:

```bash
./start-stop.sh start my-dev-profile
```

Stop all services:

```bash
./start-stop.sh stop
```

After startup, your custom service should be able to call AWS APIs using
credentials from the ECS server container.
