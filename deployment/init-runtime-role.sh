#!/bin/sh
set -eu

secret_dir=${GATEWAY_SECRET_DIR:-/run/secrets}
bootstrap_user=${POSTGRES_USER:-}
if [ -z "$bootstrap_user" ]; then
    bootstrap_user=$(cat "${POSTGRES_USER_FILE:-${secret_dir}/postgres_bootstrap_user}")
fi
bootstrap_password=$(cat "${POSTGRES_PASSWORD_FILE:-${secret_dir}/postgres_bootstrap_password}")
owner_user=$(cat "${secret_dir}/postgres_owner_user")
owner_password=$(cat "${secret_dir}/postgres_owner_password")
runtime_user=$(cat "${secret_dir}/postgres_runtime_user")
runtime_password=$(cat "${secret_dir}/postgres_runtime_password")
database_name=${POSTGRES_DB:-gateway}

valid_credential() {
    case "$1" in
        ""|*[!A-Za-z0-9_-]*) return 1 ;;
        *) return 0 ;;
    esac
}
for credential in "$bootstrap_user" "$bootstrap_password" "$owner_user" \
    "$owner_password" "$runtime_user" "$runtime_password"; do
    if ! valid_credential "$credential"; then
        echo "Database role secrets must contain only letters, digits, underscores, and hyphens" >&2
        exit 1
    fi
done
for password in "$bootstrap_password" "$owner_password" "$runtime_password"; do
    if [ "${#password}" -lt 32 ]; then
        echo "Database role passwords must contain at least 32 characters" >&2
        exit 1
    fi
done
if [ "$bootstrap_user" = "$owner_user" ] ||
    [ "$bootstrap_user" = "$runtime_user" ] ||
    [ "$owner_user" = "$runtime_user" ]; then
    echo "Database bootstrap, owner, and runtime roles must be distinct" >&2
    exit 1
fi

{
    printf '\\set bootstrap_user %s\n' "$bootstrap_user"
    printf '\\set bootstrap_password %s\n' "$bootstrap_password"
    printf '\\set owner_user %s\n' "$owner_user"
    printf '\\set owner_password %s\n' "$owner_password"
    printf '\\set runtime_user %s\n' "$runtime_user"
    printf '\\set runtime_password %s\n' "$runtime_password"
    cat <<'SQL'
\set QUIET on
\set VERBOSITY terse

SELECT format(
    'CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1 VALID UNTIL ''infinity'' PASSWORD %L',
    :'owner_user', :'owner_password'
)
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = :'owner_user')
\gexec
SELECT format(
    'CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1 VALID UNTIL ''infinity'' PASSWORD %L',
    :'runtime_user', :'runtime_password'
)
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = :'runtime_user')
\gexec
SELECT format(
    'ALTER ROLE %I WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1 VALID UNTIL ''infinity'' PASSWORD %L',
    :'owner_user', :'owner_password'
)
\gexec
SELECT format(
    'ALTER ROLE %I WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1 VALID UNTIL ''infinity'' PASSWORD %L',
    :'runtime_user', :'runtime_password'
)
\gexec
SELECT format('ALTER ROLE %I RESET ALL', :'owner_user')
\gexec
SELECT format('ALTER ROLE %I RESET ALL', :'runtime_user')
\gexec
SELECT format(
    'ALTER ROLE %I IN DATABASE %I RESET ALL',
    role.rolname, database.datname
)
FROM pg_db_role_setting settings
JOIN pg_roles role ON role.oid = settings.setrole
JOIN pg_database database ON database.oid = settings.setdatabase
WHERE role.rolname IN (:'owner_user', :'runtime_user')
\gexec
SELECT format('ALTER ROLE %I WITH PASSWORD %L', :'bootstrap_user', :'bootstrap_password')
\gexec
SELECT format(
    'REVOKE %I FROM %I GRANTED BY %I CASCADE',
    granted.rolname, member.rolname, grantor.rolname
)
FROM pg_auth_members membership
JOIN pg_roles granted ON granted.oid = membership.roleid
JOIN pg_roles member ON member.oid = membership.member
JOIN pg_roles grantor ON grantor.oid = membership.grantor
WHERE granted.rolname IN (:'bootstrap_user', :'owner_user', :'runtime_user')
   OR member.rolname IN (:'bootstrap_user', :'owner_user', :'runtime_user')
\gexec

SELECT EXISTS (
    SELECT FROM pg_extension ext
    JOIN pg_roles owner ON owner.oid = ext.extowner
    WHERE owner.rolname = :'runtime_user'
) AS runtime_owned_extension
\gset
\if :runtime_owned_extension
    \warn 'Runtime database role owns an extension; transfer or drop it as a trusted administrator'
    \quit 1
\endif

SELECT EXISTS (
    SELECT FROM pg_extension ext
    JOIN pg_roles owner ON owner.oid = ext.extowner
    WHERE owner.rolname NOT IN (:'bootstrap_user', :'owner_user')
) AS untrusted_extension_owner
\gset
\if :untrusted_extension_owner
    \warn 'An extension is not owned by the bootstrap or migration owner role'
    \quit 1
\endif

SELECT DISTINCT format(
    'REVOKE ALL PRIVILEGES ON PARAMETER %I FROM %s CASCADE',
    parameter_acl.parname,
    CASE WHEN privilege.grantee = 0 THEN 'PUBLIC'
         ELSE format('%I', grantee.rolname) END
)
FROM pg_parameter_acl parameter_acl
CROSS JOIN LATERAL aclexplode(parameter_acl.paracl) privilege
LEFT JOIN pg_roles grantee ON grantee.oid = privilege.grantee
\gexec
SELECT EXISTS (
    SELECT FROM pg_parameter_acl parameter_acl
    CROSS JOIN LATERAL aclexplode(parameter_acl.paracl) privilege
    WHERE privilege.privilege_type IN ('SET', 'ALTER SYSTEM')
) AS unsafe_parameter_acl
\gset
\if :unsafe_parameter_acl
    \warn 'PostgreSQL parameter privileges remain outside the empty allowlist'
    \quit 1
\endif

SELECT format('ALTER DATABASE %I OWNER TO %I', current_database(), :'owner_user')
\gexec
SELECT format('ALTER SCHEMA public OWNER TO %I', :'owner_user')
\gexec
SELECT format(
    CASE c.relkind
        WHEN 'S' THEN 'ALTER SEQUENCE %I.%I OWNER TO %I'
        WHEN 'v' THEN 'ALTER VIEW %I.%I OWNER TO %I'
        WHEN 'm' THEN 'ALTER MATERIALIZED VIEW %I.%I OWNER TO %I'
        WHEN 'f' THEN 'ALTER FOREIGN TABLE %I.%I OWNER TO %I'
        ELSE 'ALTER TABLE %I.%I OWNER TO %I'
    END,
    n.nspname, c.relname, :'owner_user'
)
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'S', 'v', 'm', 'f')
  AND NOT EXISTS (
      SELECT FROM pg_depend dependency
      WHERE dependency.classid = 'pg_class'::regclass
        AND dependency.objid = c.oid AND dependency.deptype = 'e'
  )
\gexec
SELECT format(
    CASE p.prokind
        WHEN 'p' THEN 'ALTER PROCEDURE %I.%I(%s) OWNER TO %I'
        WHEN 'a' THEN 'ALTER AGGREGATE %I.%I(%s) OWNER TO %I'
        ELSE 'ALTER FUNCTION %I.%I(%s) OWNER TO %I'
    END,
    n.nspname, p.proname, pg_get_function_identity_arguments(p.oid), :'owner_user'
)
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname = 'public'
  AND NOT EXISTS (
      SELECT FROM pg_depend dependency
      WHERE dependency.classid = 'pg_proc'::regclass
        AND dependency.objid = p.oid AND dependency.deptype = 'e'
  )
\gexec
SELECT format(
    CASE t.typtype
        WHEN 'd' THEN 'ALTER DOMAIN %I.%I OWNER TO %I'
        ELSE 'ALTER TYPE %I.%I OWNER TO %I'
    END,
    n.nspname, t.typname, :'owner_user'
)
FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace
WHERE n.nspname = 'public' AND t.typrelid = 0 AND t.typelem = 0
  AND NOT EXISTS (
      SELECT FROM pg_depend dependency
      WHERE dependency.classid = 'pg_type'::regclass
        AND dependency.objid = t.oid AND dependency.deptype = 'e'
  )
\gexec

SELECT EXISTS (
    SELECT FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_roles r ON r.oid = c.relowner
    WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'S', 'v', 'm', 'f')
      AND r.rolname <> :'owner_user'
      AND NOT EXISTS (
          SELECT FROM pg_depend dependency
          WHERE dependency.classid = 'pg_class'::regclass
            AND dependency.objid = c.oid AND dependency.deptype = 'e'
      )
    UNION ALL
    SELECT FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    JOIN pg_roles r ON r.oid = p.proowner
    WHERE n.nspname = 'public' AND r.rolname <> :'owner_user'
      AND NOT EXISTS (
          SELECT FROM pg_depend dependency
          WHERE dependency.classid = 'pg_proc'::regclass
            AND dependency.objid = p.oid AND dependency.deptype = 'e'
      )
    UNION ALL
    SELECT FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace
    JOIN pg_roles r ON r.oid = t.typowner
    WHERE n.nspname = 'public' AND t.typrelid = 0 AND t.typelem = 0
      AND r.rolname <> :'owner_user'
      AND NOT EXISTS (
          SELECT FROM pg_depend dependency
          WHERE dependency.classid = 'pg_type'::regclass
            AND dependency.objid = t.oid AND dependency.deptype = 'e'
      )
) AS unmanaged_public_owner
\gset
\if :unmanaged_public_owner
    \warn 'Objects in the managed public schema are not owned by the migration owner'
    \quit 1
\endif

SELECT EXISTS (
    SELECT FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl, acldefault(
        CASE WHEN c.relkind = 'S' THEN 'S'::"char" ELSE 'r'::"char" END,
        c.relowner
    ))) privilege
    JOIN pg_roles grantee ON grantee.oid = privilege.grantee
    WHERE grantee.rolname = :'runtime_user' AND n.nspname <> 'public'
    UNION ALL
    SELECT FROM pg_attribute attribute
    JOIN pg_class c ON c.oid = attribute.attrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    CROSS JOIN LATERAL aclexplode(attribute.attacl) privilege
    JOIN pg_roles grantee ON grantee.oid = privilege.grantee
    WHERE grantee.rolname = :'runtime_user' AND n.nspname <> 'public'
      AND attribute.attnum > 0 AND NOT attribute.attisdropped
    UNION ALL
    SELECT FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) privilege
    JOIN pg_roles grantee ON grantee.oid = privilege.grantee
    WHERE grantee.rolname = :'runtime_user' AND n.nspname <> 'public'
    UNION ALL
    SELECT FROM pg_namespace n
    CROSS JOIN LATERAL aclexplode(COALESCE(n.nspacl, acldefault('n', n.nspowner))) privilege
    JOIN pg_roles grantee ON grantee.oid = privilege.grantee
    WHERE grantee.rolname = :'runtime_user' AND n.nspname <> 'public'
    UNION ALL
    SELECT FROM pg_type t
    JOIN pg_namespace n ON n.oid = t.typnamespace
    CROSS JOIN LATERAL aclexplode(COALESCE(t.typacl, acldefault('T', t.typowner))) privilege
    JOIN pg_roles grantee ON grantee.oid = privilege.grantee
    WHERE grantee.rolname = :'runtime_user' AND n.nspname <> 'public'
    UNION ALL
    SELECT FROM pg_default_acl defaults
    CROSS JOIN LATERAL aclexplode(defaults.defaclacl) privilege
    JOIN pg_roles grantee ON grantee.oid = privilege.grantee
    LEFT JOIN pg_namespace n ON n.oid = defaults.defaclnamespace
    WHERE grantee.rolname = :'runtime_user'
      AND COALESCE(n.nspname, '') <> 'public'
    UNION ALL
    SELECT FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_roles owner ON owner.oid = c.relowner
    WHERE owner.rolname = :'runtime_user' AND n.nspname <> 'public'
    UNION ALL
    SELECT FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    JOIN pg_roles owner ON owner.oid = p.proowner
    WHERE owner.rolname = :'runtime_user' AND n.nspname <> 'public'
    UNION ALL
    SELECT FROM pg_namespace n JOIN pg_roles owner ON owner.oid = n.nspowner
    WHERE owner.rolname = :'runtime_user' AND n.nspname <> 'public'
    UNION ALL
    SELECT FROM pg_database database
    CROSS JOIN LATERAL aclexplode(COALESCE(
        database.datacl, acldefault('d', database.datdba)
    )) privilege
    JOIN pg_roles grantee ON grantee.oid = privilege.grantee
    WHERE grantee.rolname = :'runtime_user'
      AND database.datname <> current_database()
    UNION ALL
    SELECT FROM pg_database database JOIN pg_roles owner ON owner.oid = database.datdba
    WHERE owner.rolname = :'runtime_user'
) AS runtime_privilege_outside_managed_schema
\gset
\if :runtime_privilege_outside_managed_schema
    \warn 'Runtime role has direct privileges outside the managed public schema'
    \quit 1
\endif

SELECT DISTINCT format(
    'REVOKE ALL PRIVILEGES ON DATABASE %I FROM %s CASCADE',
    database.datname,
    CASE WHEN privilege.grantee = 0 THEN 'PUBLIC'
         ELSE format('%I', grantee.rolname) END
)
FROM pg_database database
CROSS JOIN LATERAL aclexplode(COALESCE(
    database.datacl, acldefault('d', database.datdba)
)) privilege
LEFT JOIN pg_roles grantee ON grantee.oid = privilege.grantee
WHERE database.datname = current_database()
  AND privilege.grantee <> database.datdba
\gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), :'runtime_user')
\gexec

SELECT DISTINCT format(
    'REVOKE ALL PRIVILEGES ON SCHEMA %I FROM %s CASCADE',
    namespace.nspname,
    CASE WHEN privilege.grantee = 0 THEN 'PUBLIC'
         ELSE format('%I', grantee.rolname) END
)
FROM pg_namespace namespace
CROSS JOIN LATERAL aclexplode(COALESCE(
    namespace.nspacl, acldefault('n', namespace.nspowner)
)) privilege
LEFT JOIN pg_roles grantee ON grantee.oid = privilege.grantee
WHERE namespace.nspname = 'public'
  AND privilege.grantee <> namespace.nspowner
\gexec
SELECT format('GRANT USAGE ON SCHEMA public TO %I', :'runtime_user')
\gexec

SELECT DISTINCT format(
    'REVOKE ALL PRIVILEGES ON %s %I.%I FROM %s CASCADE',
    CASE WHEN relation.relkind = 'S' THEN 'SEQUENCE' ELSE 'TABLE' END,
    namespace.nspname, relation.relname,
    CASE WHEN privilege.grantee = 0 THEN 'PUBLIC'
         ELSE format('%I', grantee.rolname) END
)
FROM pg_class relation
JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
CROSS JOIN LATERAL aclexplode(COALESCE(
    relation.relacl,
    acldefault(
        CASE WHEN relation.relkind = 'S' THEN 'S'::"char" ELSE 'r'::"char" END,
        relation.relowner
    )
)) privilege
LEFT JOIN pg_roles grantee ON grantee.oid = privilege.grantee
WHERE namespace.nspname = 'public'
  AND relation.relkind IN ('r', 'p', 'S', 'v', 'm', 'f')
  AND privilege.grantee <> relation.relowner
  AND NOT EXISTS (
      SELECT FROM pg_depend dependency
      WHERE dependency.classid = 'pg_class'::regclass
        AND dependency.objid = relation.oid AND dependency.deptype = 'e'
  )
\gexec
SELECT DISTINCT format(
    'REVOKE ALL PRIVILEGES (%I) ON TABLE %I.%I FROM %s CASCADE',
    attribute.attname, namespace.nspname, relation.relname,
    CASE WHEN privilege.grantee = 0 THEN 'PUBLIC'
         ELSE format('%I', grantee.rolname) END
)
FROM pg_attribute attribute
JOIN pg_class relation ON relation.oid = attribute.attrelid
JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
CROSS JOIN LATERAL aclexplode(attribute.attacl) privilege
LEFT JOIN pg_roles grantee ON grantee.oid = privilege.grantee
WHERE namespace.nspname = 'public'
  AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
  AND attribute.attnum > 0 AND NOT attribute.attisdropped
  AND privilege.grantee <> relation.relowner
  AND NOT EXISTS (
      SELECT FROM pg_depend dependency
      WHERE dependency.classid = 'pg_class'::regclass
        AND dependency.objid = relation.oid AND dependency.deptype = 'e'
  )
\gexec
SELECT DISTINCT format(
    'REVOKE ALL PRIVILEGES ON ROUTINE %I.%I(%s) FROM %s CASCADE',
    namespace.nspname, routine.proname,
    pg_get_function_identity_arguments(routine.oid),
    CASE WHEN privilege.grantee = 0 THEN 'PUBLIC'
         ELSE format('%I', grantee.rolname) END
)
FROM pg_proc routine
JOIN pg_namespace namespace ON namespace.oid = routine.pronamespace
CROSS JOIN LATERAL aclexplode(COALESCE(
    routine.proacl, acldefault('f', routine.proowner)
)) privilege
LEFT JOIN pg_roles grantee ON grantee.oid = privilege.grantee
WHERE namespace.nspname = 'public'
  AND privilege.grantee <> routine.proowner
  AND NOT EXISTS (
      SELECT FROM pg_depend dependency
      WHERE dependency.classid = 'pg_proc'::regclass
        AND dependency.objid = routine.oid AND dependency.deptype = 'e'
  )
\gexec
SELECT DISTINCT format(
    'REVOKE ALL PRIVILEGES ON TYPE %I.%I FROM %s CASCADE',
    namespace.nspname, type.typname,
    CASE WHEN privilege.grantee = 0 THEN 'PUBLIC'
         ELSE format('%I', grantee.rolname) END
)
FROM pg_type type
JOIN pg_namespace namespace ON namespace.oid = type.typnamespace
CROSS JOIN LATERAL aclexplode(COALESCE(
    type.typacl, acldefault('T', type.typowner)
)) privilege
LEFT JOIN pg_roles grantee ON grantee.oid = privilege.grantee
WHERE namespace.nspname = 'public'
  AND type.typrelid = 0 AND type.typelem = 0
  AND privilege.grantee <> type.typowner
  AND NOT EXISTS (
      SELECT FROM pg_depend dependency
      WHERE dependency.classid = 'pg_type'::regclass
        AND dependency.objid = type.oid AND dependency.deptype = 'e'
  )
\gexec

SELECT DISTINCT format(
    'ALTER DEFAULT PRIVILEGES FOR ROLE %I%s REVOKE ALL PRIVILEGES ON %s FROM %s',
    creator.rolname,
    CASE WHEN defaults.defaclnamespace = 0 THEN ''
         ELSE format(' IN SCHEMA %I', namespace.nspname) END,
    CASE defaults.defaclobjtype
        WHEN 'r' THEN 'TABLES'
        WHEN 'S' THEN 'SEQUENCES'
        WHEN 'f' THEN 'FUNCTIONS'
        WHEN 'T' THEN 'TYPES'
        WHEN 'n' THEN 'SCHEMAS'
    END,
    CASE WHEN privilege.grantee = 0 THEN 'PUBLIC'
         ELSE format('%I', grantee.rolname) END
)
FROM pg_default_acl defaults
JOIN pg_roles creator ON creator.oid = defaults.defaclrole
LEFT JOIN pg_namespace namespace ON namespace.oid = defaults.defaclnamespace
CROSS JOIN LATERAL aclexplode(defaults.defaclacl) privilege
LEFT JOIN pg_roles grantee ON grantee.oid = privilege.grantee
WHERE creator.rolname IN (:'owner_user', :'bootstrap_user')
  AND (
      defaults.defaclnamespace = 0
      OR namespace.nspname = 'public'
      OR defaults.defaclobjtype = 'f'
  )
  AND defaults.defaclobjtype IN ('r', 'S', 'f', 'T', 'n')
  AND privilege.grantee <> creator.oid
\gexec
SELECT format(
    'ALTER DEFAULT PRIVILEGES FOR ROLE %I REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC',
    creator.name
)
FROM (VALUES (:'owner_user'), (:'bootstrap_user')) creator(name)
\gexec

SELECT format(
    CASE WHEN relation.relkind = 'm'
         THEN 'GRANT SELECT ON TABLE %I.%I TO %I'
         ELSE 'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE %I.%I TO %I'
    END,
    namespace.nspname, relation.relname, :'runtime_user'
)
FROM pg_class relation
JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
WHERE namespace.nspname = 'public'
  AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
  AND NOT EXISTS (
      SELECT FROM pg_depend dependency
      WHERE dependency.classid = 'pg_class'::regclass
        AND dependency.objid = relation.oid AND dependency.deptype = 'e'
  )
\gexec
SELECT format(
    'GRANT USAGE, SELECT, UPDATE ON SEQUENCE %I.%I TO %I',
    namespace.nspname, relation.relname, :'runtime_user'
)
FROM pg_class relation
JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
WHERE namespace.nspname = 'public' AND relation.relkind = 'S'
  AND NOT EXISTS (
      SELECT FROM pg_depend dependency
      WHERE dependency.classid = 'pg_class'::regclass
        AND dependency.objid = relation.oid AND dependency.deptype = 'e'
  )
\gexec
SELECT format(
    'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %I',
    :'owner_user', :'runtime_user'
)
\gexec
SELECT format(
    'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO %I',
    :'owner_user', :'runtime_user'
)
\gexec

SELECT EXISTS (
    SELECT FROM pg_database database JOIN pg_roles role ON role.oid = database.datdba
    WHERE role.rolname = :'runtime_user'
    UNION ALL
    SELECT FROM pg_namespace namespace JOIN pg_roles role ON role.oid = namespace.nspowner
    WHERE role.rolname = :'runtime_user'
    UNION ALL
    SELECT FROM pg_class relation JOIN pg_roles role ON role.oid = relation.relowner
    WHERE role.rolname = :'runtime_user'
    UNION ALL
    SELECT FROM pg_proc routine JOIN pg_roles role ON role.oid = routine.proowner
    WHERE role.rolname = :'runtime_user'
    UNION ALL
    SELECT FROM pg_type managed_type JOIN pg_roles role ON role.oid = managed_type.typowner
    WHERE role.rolname = :'runtime_user'
    UNION ALL
    SELECT FROM pg_extension ext JOIN pg_roles role ON role.oid = ext.extowner
    WHERE role.rolname = :'runtime_user'
) AS runtime_is_privileged
\gset
\if :runtime_is_privileged
    \warn 'Runtime database role owns database objects or extensions'
    \quit 1
\endif

WITH runtime AS (
    SELECT oid FROM pg_roles WHERE rolname = :'runtime_user'
)
SELECT EXISTS (
    SELECT FROM pg_database database
    CROSS JOIN runtime
    CROSS JOIN LATERAL aclexplode(COALESCE(
        database.datacl, acldefault('d', database.datdba)
    )) privilege
    WHERE database.datname = current_database()
      AND NOT (
          privilege.grantee = database.datdba
          OR (
              privilege.grantee = runtime.oid
              AND privilege.privilege_type = 'CONNECT'
              AND NOT privilege.is_grantable
          )
      )
    UNION ALL
    SELECT FROM pg_namespace namespace
    CROSS JOIN runtime
    CROSS JOIN LATERAL aclexplode(COALESCE(
        namespace.nspacl, acldefault('n', namespace.nspowner)
    )) privilege
    WHERE namespace.nspname = 'public'
      AND NOT (
          privilege.grantee = namespace.nspowner
          OR (
              privilege.grantee = runtime.oid
              AND privilege.privilege_type = 'USAGE'
              AND NOT privilege.is_grantable
          )
      )
    UNION ALL
    SELECT FROM pg_class relation
    JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
    CROSS JOIN runtime
    CROSS JOIN LATERAL aclexplode(COALESCE(
        relation.relacl,
        acldefault(
            CASE WHEN relation.relkind = 'S' THEN 'S'::"char" ELSE 'r'::"char" END,
            relation.relowner
        )
    )) privilege
    WHERE namespace.nspname = 'public'
      AND relation.relkind IN ('r', 'p', 'S', 'v', 'm', 'f')
      AND NOT EXISTS (
          SELECT FROM pg_depend dependency
          WHERE dependency.classid = 'pg_class'::regclass
            AND dependency.objid = relation.oid AND dependency.deptype = 'e'
      )
      AND NOT (
          privilege.grantee = relation.relowner
          OR (
              privilege.grantee = runtime.oid
              AND NOT privilege.is_grantable
              AND (
                  (
                      relation.relkind = 'S'
                      AND privilege.privilege_type IN ('USAGE', 'SELECT', 'UPDATE')
                  )
                  OR (
                      relation.relkind = 'm'
                      AND privilege.privilege_type = 'SELECT'
                  )
                  OR (
                      relation.relkind IN ('r', 'p', 'v', 'f')
                      AND privilege.privilege_type IN ('SELECT', 'INSERT', 'UPDATE', 'DELETE')
                  )
              )
          )
      )
    UNION ALL
    SELECT FROM pg_attribute attribute
    JOIN pg_class relation ON relation.oid = attribute.attrelid
    JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
    CROSS JOIN LATERAL aclexplode(attribute.attacl) privilege
    WHERE namespace.nspname = 'public'
      AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
      AND attribute.attnum > 0 AND NOT attribute.attisdropped
      AND privilege.grantee <> relation.relowner
      AND NOT EXISTS (
          SELECT FROM pg_depend dependency
          WHERE dependency.classid = 'pg_class'::regclass
            AND dependency.objid = relation.oid AND dependency.deptype = 'e'
      )
    UNION ALL
    SELECT FROM pg_proc routine
    JOIN pg_namespace namespace ON namespace.oid = routine.pronamespace
    CROSS JOIN LATERAL aclexplode(COALESCE(
        routine.proacl, acldefault('f', routine.proowner)
    )) privilege
    WHERE namespace.nspname = 'public'
      AND privilege.grantee <> routine.proowner
      AND NOT EXISTS (
          SELECT FROM pg_depend dependency
          WHERE dependency.classid = 'pg_proc'::regclass
            AND dependency.objid = routine.oid AND dependency.deptype = 'e'
      )
    UNION ALL
    SELECT FROM pg_type type
    JOIN pg_namespace namespace ON namespace.oid = type.typnamespace
    CROSS JOIN LATERAL aclexplode(COALESCE(
        type.typacl, acldefault('T', type.typowner)
    )) privilege
    WHERE namespace.nspname = 'public'
      AND type.typrelid = 0 AND type.typelem = 0
      AND privilege.grantee <> type.typowner
      AND NOT EXISTS (
          SELECT FROM pg_depend dependency
          WHERE dependency.classid = 'pg_type'::regclass
            AND dependency.objid = type.oid AND dependency.deptype = 'e'
      )
) AS unsafe_managed_acl
\gset
\if :unsafe_managed_acl
    \warn 'Managed database, schema, or object ACLs are unsafe'
    \quit 1
\endif

WITH creators AS (
    SELECT oid, rolname FROM pg_roles
    WHERE rolname IN (:'owner_user', :'bootstrap_user')
), runtime AS (
    SELECT oid FROM pg_roles WHERE rolname = :'runtime_user'
)
SELECT EXISTS (
    SELECT FROM pg_default_acl defaults
    JOIN creators creator ON creator.oid = defaults.defaclrole
    LEFT JOIN pg_namespace namespace ON namespace.oid = defaults.defaclnamespace
    CROSS JOIN runtime
    CROSS JOIN LATERAL aclexplode(defaults.defaclacl) privilege
    WHERE (
        defaults.defaclnamespace = 0
        OR namespace.nspname = 'public'
        OR defaults.defaclobjtype = 'f'
    )
      AND defaults.defaclobjtype IN ('r', 'S', 'f', 'T', 'n')
      AND NOT (
          privilege.grantee = creator.oid
          OR (
              creator.rolname = :'owner_user'
              AND namespace.nspname = 'public'
              AND privilege.grantee = runtime.oid
              AND NOT privilege.is_grantable
              AND (
                  (
                      defaults.defaclobjtype = 'r'
                      AND privilege.privilege_type IN ('SELECT', 'INSERT', 'UPDATE', 'DELETE')
                  )
                  OR (
                      defaults.defaclobjtype = 'S'
                      AND privilege.privilege_type IN ('USAGE', 'SELECT', 'UPDATE')
                  )
              )
          )
      )
    UNION ALL
    SELECT FROM creators creator
    CROSS JOIN LATERAL aclexplode(COALESCE(
        (
            SELECT defaults.defaclacl
            FROM pg_default_acl defaults
            WHERE defaults.defaclrole = creator.oid
              AND defaults.defaclnamespace = 0
              AND defaults.defaclobjtype = 'f'
        ),
        acldefault('f', creator.oid)
    )) privilege
    WHERE privilege.grantee = 0
      AND privilege.privilege_type = 'EXECUTE'
) AS unsafe_default_acl
\gset
\if :unsafe_default_acl
    \warn 'Owner or bootstrap default privileges are unsafe'
    \quit 1
\endif

SELECT NOT (
    owner.rolcanlogin AND NOT owner.rolsuper AND NOT owner.rolcreatedb
    AND NOT owner.rolcreaterole AND NOT owner.rolinherit
    AND NOT owner.rolreplication AND NOT owner.rolbypassrls
    AND owner.rolconnlimit = -1
    AND owner.rolvaliduntil = 'infinity'::timestamptz
    AND runtime.rolcanlogin AND NOT runtime.rolsuper AND NOT runtime.rolcreatedb
    AND NOT runtime.rolcreaterole AND NOT runtime.rolinherit
    AND NOT runtime.rolreplication AND NOT runtime.rolbypassrls
    AND runtime.rolconnlimit = -1
    AND runtime.rolvaliduntil = 'infinity'::timestamptz
    AND owner.rolconfig IS NULL
    AND runtime.rolconfig IS NULL
    AND NOT EXISTS (
        SELECT FROM pg_db_role_setting settings
        WHERE settings.setrole IN (owner.oid, runtime.oid)
    )
    AND NOT EXISTS (
        SELECT FROM pg_auth_members membership
        WHERE membership.roleid IN (bootstrap.oid, owner.oid, runtime.oid)
           OR membership.member IN (bootstrap.oid, owner.oid, runtime.oid)
    )
) AS unsafe_role_attributes
FROM pg_roles bootstrap CROSS JOIN pg_roles owner CROSS JOIN pg_roles runtime
WHERE bootstrap.rolname = :'bootstrap_user'
  AND owner.rolname = :'owner_user'
  AND runtime.rolname = :'runtime_user'
\gset
\if :unsafe_role_attributes
    \warn 'Bootstrap, owner, or runtime role settings, attributes, or memberships are unsafe'
    \quit 1
\endif
SQL
} | psql --username "$bootstrap_user" --dbname "$database_name" --no-psqlrc \
    --set=ON_ERROR_STOP=1

unset bootstrap_user bootstrap_password owner_user owner_password runtime_user runtime_password
