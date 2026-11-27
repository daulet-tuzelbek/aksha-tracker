#!/usr/bin/env bash
# Резервная копия базы (в ней только зашифрованные данные) в server/data/backup-ДАТА.db
set -euo pipefail
cd "$(dirname "$0")"
F="backup-$(date +%F-%H%M).db"
docker compose exec -T api node --no-warnings -e "new (require('node:sqlite').DatabaseSync)('/data/aksha.db').exec(\"VACUUM INTO '/data/$F'\")"
echo "Сохранено: server/data/$F"
