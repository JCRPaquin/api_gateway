#!/bin/sh
set -eu

secret_dir=${GATEWAY_SECRET_DIR:-/run/secrets}
username=$(cat "${secret_dir}/redis_username")
password=$(cat "${secret_dir}/redis_password")

case "$username" in
    ""|*[!A-Za-z0-9_-]*)
        echo "Redis ACL username must contain only letters, digits, underscores, and hyphens" >&2
        exit 1
        ;;
esac
case "$password" in
    ""|*[!A-Za-z0-9_-]*)
        echo "Redis ACL password must contain only letters, digits, underscores, and hyphens" >&2
        exit 1
        ;;
esac
if [ "${#password}" -lt 32 ]; then
    echo "Redis ACL password must contain at least 32 characters" >&2
    exit 1
fi

umask 077
runtime_dir=${GATEWAY_RUNTIME_DIR:-/tmp}
acl_file=${runtime_dir}/gateway-redis.acl
# Keep key patterns synchronized with the JSON-codec storage/cache prefixes and
# Flask-Limiter's LIMITS namespace. Add commands only with a caller regression.
{
    printf '%s\n' 'user default off'
    printf 'user %s on >%s resetkeys resetchannels -@all' "$username" "$password"
    printf ' ~gateway:storage:v1:* ~gateway:cache:v1:* ~LIMITS:*'
    printf ' +ping +select +get +mget +set +setex +psetex +del +unlink'
    printf ' +exists +incr +incrby +incrbyfloat +expire +pexpire +persist'
    printf ' +ttl +pttl +keys +scan +multi +exec +discard +evalsha +script|load\n'
} >"$acl_file"
unset password

exec redis-server --aclfile "$acl_file" --protected-mode yes --bind 0.0.0.0
