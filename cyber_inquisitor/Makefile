SHELL			:= bash
COMPOSE			:= docker compose
INSPECT			:= docker inspect -f
NET_SETTINGS	:= .NetworkSettings.Networks

all: up

build:
	@$(COMPOSE) build --no-cache client inquisitor

up:
	@mkdir -p server_files
	@$(COMPOSE) up -d --wait client server; \
	MAC_CLIENT=$$($(INSPECT) '{{range $(NET_SETTINGS)}}{{.MacAddress}}{{end}}' client); \
	MAC_SERVER=$$($(INSPECT) '{{range $(NET_SETTINGS)}}{{.MacAddress}}{{end}}' server); \
	MAC_CLIENT=$$MAC_CLIENT MAC_SERVER=$$MAC_SERVER $(COMPOSE) up inquisitor

down:
	@$(COMPOSE) down
	@sudo rm -rf server_files

kill:
	docker kill --signal=SIGTERM inquisitor

.PHONY: all build up down kill
