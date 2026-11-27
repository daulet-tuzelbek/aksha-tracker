#!/usr/bin/env bash
# Обновить приложение и сервер до последней версии из GitHub.
set -euo pipefail
cd "$(dirname "$0")/.."
git pull --ff-only
cd server
docker compose up -d --force-recreate
docker compose ps
