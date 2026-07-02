#!/bin/sh -e

run() {
	echo run $EXPERIMENT_ID
	echo run $EXPERIMENT_ID
	docker compose up -d
	WAIT=180
	echo -n Waiting "$WAIT" seconds. Press any key to cancel:
	read -sn1 -t "$WAIT" || true
	echo stopping
	docker compose down
	docker volume rm $(docker volume ls | sed -n 's/local *//;/^nerve_/p' | cut -f1 -d' ')
}

for i in 0 1 2; do
COMPOSE_PROFILES=nehws OPEN_REGISTRATION=true EXPERIMENT_ID=nehws run
COMPOSE_PROFILES=synapse SHARED_REGISTRATION_SECRET=secret1 EXPERIMENT_ID=synapse run
done
