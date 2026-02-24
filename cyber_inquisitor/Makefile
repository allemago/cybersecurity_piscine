COMPOSE		:= docker compose

all: up

up:
	$(COMPOSE) up -d --wait client server
	$(eval VARS := $(shell bash get_mac.sh))
	$(eval MAC_CLIENT := $(word 1, $(VARS)))
	$(eval MAC_SERVER := $(word 2, $(VARS)))
    MAC_CLIENT=$(MAC_CLIENT) MAC_SERVER=$(MAC_SERVER) $(COMPOSE) up -d --wait inquisitor

down:
	$(COMPOSE) down

.PHONY: all up down
