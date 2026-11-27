#!/usr/bin/env bash
# Ақша Трекер: установка на чистый Ubuntu 24.04. Запуск: sudo bash install.sh ваш-домен.kz
set -euo pipefail
DOMAIN="${1:-}"
if [ -z "$DOMAIN" ]; then echo "Укажите домен: sudo bash install.sh aksha.example.kz"; exit 1; fi
if ! command -v docker >/dev/null; then curl -fsSL https://get.docker.com | sh; fi
cd "$(dirname "$0")"
echo "DOMAIN=$DOMAIN" > .env
mkdir -p data
if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then ufw allow 80/tcp; ufw allow 443/tcp; fi
docker compose up -d --force-recreate
sleep 5
docker compose ps
echo
echo "Готово. Через 1-2 минуты откройте https://$DOMAIN"
