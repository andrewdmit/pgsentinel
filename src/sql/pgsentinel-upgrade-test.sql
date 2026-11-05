CREATE EXTENSION pg_stat_statements;
CREATE EXTENSION pgsentinel_nx VERSION '1.4.1';
SET pg_stat_statements.track = 'all';

SELECT pg_sleep(3);
SELECT count(*) > 0 AS has_old_api_data
FROM pg_active_session_history;
\! sleep 2
SELECT count(*) > 0 AS has_old_api_pgssh_data
FROM pg_stat_statements_history;
SELECT prosrc
FROM pg_proc
WHERE oid = 'pg_active_session_history()'::regprocedure;

ALTER EXTENSION pgsentinel_nx UPDATE TO '1.5.1';

SELECT extversion
FROM pg_extension
WHERE extname = 'pgsentinel_nx';
SELECT prosrc
FROM pg_proc
WHERE oid = 'pg_active_session_history()'::regprocedure;
SELECT count(*) > 0 AS has_legacy_v1_5_data
FROM pg_active_session_history;

CREATE VIEW pgsentinel_ash_dependency AS
SELECT * FROM pg_active_session_history;

ALTER EXTENSION pgsentinel_nx UPDATE;

SELECT extversion
FROM pg_extension
WHERE extname = 'pgsentinel_nx';
SELECT prosrc
FROM pg_proc
WHERE oid = 'pg_active_session_history()'::regprocedure;
SELECT count(*) = 29 AS has_new_api_columns
FROM pg_attribute
WHERE attrelid = 'pg_active_session_history'::regclass
  AND attnum > 0
  AND NOT attisdropped;

DROP VIEW pgsentinel_ash_dependency;
DROP EXTENSION pgsentinel_nx;
DROP EXTENSION pg_stat_statements;
