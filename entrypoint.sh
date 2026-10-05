#!/bin/bash
set -e

if [ "$WAF_MODE" = "on" ]; then
  echo "[lab_nginx] WAF: ENABLED (naive signature blocking)"
  export WAF_ACTION='return 403 "Blocked by lab WAF\n";'
else
  echo "[lab_nginx] WAF: DISABLED (pure reverse proxy / cache)"
  export WAF_ACTION=''
fi

envsubst '${WAF_ACTION}' < /etc/nginx/nginx.conf.template > /etc/nginx/nginx.conf

exec nginx -g 'daemon off;'
