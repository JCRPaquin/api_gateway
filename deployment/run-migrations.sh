#!/bin/sh
set -eu

max_attempts=${MIGRATION_MAX_ATTEMPTS:-6}
case "$max_attempts" in
    ""|*[!0-9]*|0)
        echo "MIGRATION_MAX_ATTEMPTS must be a positive integer" >&2
        exit 2
        ;;
esac

attempt=1
delay=1
while ! alembic upgrade head; do
    if [ "$attempt" -ge "$max_attempts" ]; then
        echo "Database migration failed after ${attempt} attempts" >&2
        exit 1
    fi
    echo "Database migration attempt ${attempt} failed; retrying in ${delay}s" >&2
    sleep "$delay"
    attempt=$((attempt + 1))
    if [ "$delay" -lt 16 ]; then
        delay=$((delay * 2))
    fi
done
