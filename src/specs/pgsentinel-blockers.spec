# Blocker reporting in pg_active_session_history.
#
# The sampler asks pg_blocking_pids() who blocks each active session and looks
# up the first blocker's state among the rows pg_stat_get_activity() returned.
# Hold locks from other sessions, let the sampler catch a waiter, and compare
# what it recorded with pg_blocking_pids() and with the waiter's own
# pg_stat_activity row.
#
# Checks run in DO blocks that raise with the offending sample instead of
# returning rows: isolationtester prints result sets differently before and
# after PostgreSQL 14, and this keeps one expected file for every version.

setup
{
    CREATE EXTENSION IF NOT EXISTS pgsentinel;
    CREATE TABLE ash_lock_target (id int);
    INSERT INTO ash_lock_target VALUES (1);

    -- Wait for a sample of the session named ash_waiter that the sampler took
    -- after this call started, while the waiter was blocked, then check it.
    CREATE FUNCTION ash_check_blocked(expected_blockers int,
                                      expected_wait_event text,
                                      expected_cmdtype text)
    RETURNS void LANGUAGE plpgsql AS $$
    DECLARE
        waiter  int;
        holders int[];
        core    int[];
        since   timestamptz := clock_timestamp();
        s       record;
        sampled bool := false;
    BEGIN
        SELECT a.pid INTO waiter
          FROM pg_stat_activity a WHERE a.application_name = 'ash_waiter';
        SELECT array_agg(a.pid) INTO holders
          FROM pg_stat_activity a
         WHERE a.application_name LIKE 'ash_holder%'
           AND a.state = 'idle in transaction';
        core := pg_blocking_pids(waiter);

        -- The sampler runs once a second; allow a slow machine a minute.
        -- (Test FOUND inside the loop: a FOR loop sets it on exit.)
        FOR i IN 1..600 LOOP
            SELECT * INTO s
              FROM pg_active_session_history h
             WHERE h.pid = waiter AND h.ash_time >= since
             ORDER BY h.ash_time DESC
             LIMIT 1;
            IF FOUND THEN
                sampled := true;
                EXIT;
            END IF;
            PERFORM pg_sleep(0.1);
        END LOOP;
        IF NOT sampled THEN
            RAISE EXCEPTION 'pgsentinel recorded no sample of the blocked session within 60 seconds';
        END IF;

        -- Any NULL here is a failure, hence coalesce over a single AND chain.
        IF NOT coalesce(
               cardinality(core) = expected_blockers
           AND s.blockers = expected_blockers
           AND s.blockerpid = ANY (core)
           AND s.blockerpid = ANY (holders)
           AND s.blocker_state = 'idle in transaction'
           AND s.state = 'active'
           AND s.wait_event_type = 'Lock'
           AND s.wait_event = expected_wait_event
           AND s.cmdtype = expected_cmdtype
           AND s.datname = current_database()::text
           AND s.usename = current_user::text
           AND s.backend_type = 'client backend'
           AND s.client_port IS NOT NULL
           AND s.queryid IS NOT NULL,
           false)
        THEN
            RAISE EXCEPTION 'unexpected sample: holders %, pg_blocking_pids %, recorded %',
                holders, core, row_to_json(s);
        END IF;
    END
    $$;
}

teardown
{
    DROP FUNCTION ash_check_blocked(int, text, text);
    DROP TABLE ash_lock_target;
    DROP EXTENSION pgsentinel;
}

session holder1
setup       { SET application_name = 'ash_holder1'; }
step h1_row     { BEGIN; UPDATE ash_lock_target SET id = id; }
step h1_share   { BEGIN; LOCK TABLE ash_lock_target IN ACCESS SHARE MODE; }
step h1_commit  { COMMIT; }

session holder2
setup       { SET application_name = 'ash_holder2'; }
step h2_share   { BEGIN; LOCK TABLE ash_lock_target IN ACCESS SHARE MODE; }
step h2_commit  { COMMIT; }

session waiter
setup       { SET application_name = 'ash_waiter'; }
# Waits on holder1's transaction id, after parse analysis, so the parse hook
# has already recorded this UPDATE.
step w_row      { UPDATE ash_lock_target SET id = id; }
# Waits for both shared locks to go away.
step w_excl     { BEGIN; LOCK TABLE ash_lock_target IN ACCESS EXCLUSIVE MODE; }
step w_commit   { COMMIT; }

session observer
step o_row      { DO $$ BEGIN PERFORM ash_check_blocked(1, 'transactionid', 'UPDATE'); END $$; }
step o_excl     { DO $$ BEGIN PERFORM ash_check_blocked(2, 'relation', 'UTILITY'); END $$; }

# One blocker on a row.
permutation h1_row w_row o_row h1_commit

# Two blockers on the table: blockers counts both, blockerpid is one of them.
permutation h1_share h2_share w_excl o_excl h1_commit h2_commit w_commit
