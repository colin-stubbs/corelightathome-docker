#!/bin/bash

# remove any existing container if something has changed
docker compose -f ./docker-compose.yml rm

# build the container
# fix perms on custom entrypoint as these may have been lost...
chmod 0755 container/docker-entrypoint.sh

# build a new container if necessary
# NOTE: cached layers may be used if there's no modifications in container/Dockerfile and related files
docker compose -f ./docker-compose.yml build

# EOF
