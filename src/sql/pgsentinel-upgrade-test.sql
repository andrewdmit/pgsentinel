-- Upgrading the library before the extension.
--
-- After installing a new pgsentinel library and restarting, the SQL definition
-- stays at the old version until ALTER EXTENSION ... UPDATE. Reading the view
-- in that window must fail with a hint, not crash the server: 1.4.1's
-- definition lacks nested_queryid, and filling it with the current row once
-- dereferenced an int8 as a text pointer.

CREATE EXTENSION pgsentinel VERSION '1.4.1';

-- Give the sampler something to store, so the view has rows to return.
SELECT pg_sleep(2);

SELECT count(*) FROM pg_active_session_history;

ALTER EXTENSION pgsentinel UPDATE;
SELECT e.extversion = a.default_version AS updated_to_default
  FROM pg_extension e JOIN pg_available_extensions a ON a.name = e.extname
 WHERE e.extname = 'pgsentinel';

SELECT pg_sleep(2);
SELECT count(*) > 0 AS has_data FROM pg_active_session_history;
SELECT count(nested_queryid) > 0 AS has_nested_queryid FROM pg_active_session_history;

DROP EXTENSION pgsentinel;
