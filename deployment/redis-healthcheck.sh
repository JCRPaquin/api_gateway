#!/bin/sh
set -eu

# A healthy deployment must reject the unauthenticated path as well as accept
# the named application ACL user.
unauthenticated_response=$(redis-cli -h 127.0.0.1 ping 2>/dev/null || true)
if [ "$unauthenticated_response" = "PONG" ]; then
    exit 1
fi

secret_dir=${GATEWAY_SECRET_DIR:-/run/secrets}
username=$(cat "${secret_dir}/redis_username")
password=$(cat "${secret_dir}/redis_password")
response=$(REDISCLI_AUTH="$password" redis-cli \
    --no-auth-warning --user "$username" -h 127.0.0.1 ping 2>/dev/null)
unset password
[ "$response" = "PONG" ]
