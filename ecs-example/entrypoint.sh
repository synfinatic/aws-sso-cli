#!/bin/sh 
# The  entrypoint.sh script is the entry point for the container. It starts the AWS SSO ECS service and then runs the actual service. 
/usr/bin/aws-sso ecs run --ip=0.0.0.0 &

# run your actual service here 
while true; do 
    sleep 9999999
done
 