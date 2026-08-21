#!/bin/bash
# Loads .env (OAuth client id/secret) and starts the Auth Service.
# Usage: ./run.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ -f .env ]; then
  set -a
  source .env
  set +a
else
  echo "Warning: .env not found - Google/GitHub OAuth endpoints won't work, everything else will."
fi

docker start vingdom-users-db > /dev/null 2>&1 || echo "Warning: could not start vingdom-users-db - is it created yet?"

./mvnw spring-boot:run
