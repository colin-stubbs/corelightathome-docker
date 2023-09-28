# remove any old containers
docker compose -f ./docker-compose.yml rm

# build the container
# fix perms on custom entrypoint as these may have been lost...
chmod 0755 container/docker-entrypoint.sh
docker compose -f ./docker-compose.yml build
