# remove any old containers
docker compose -f ./docker-compose.yml rm

# build the container
docker compose -f ./docker-compose.yml build
