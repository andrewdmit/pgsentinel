CREATE EXTENSION pg_stat_statements;
CREATE EXTENSION pgsentinel_nx;

select pg_sleep(3);
select count(*) > 0 AS has_data from pg_active_session_history where queryid in (select queryid from pg_stat_statements);
select count(*) > 0 AS has_pgssh_data from pg_stat_statements_history;

DROP EXTENSION pgsentinel_nx;
DROP EXTENSION pg_stat_statements;
