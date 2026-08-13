/*
 * pgsentinel.c
 *   Track active session history.
 *
 * Copyright (c) 2018-2026, PgSentinel
 *
 * IDENTIFICATION:
 * https://github.com/pgsentinel/pgsentinel
 *
 * This program is open source, licensed under the PostgreSQL license.
 * For license terms, see the LICENSE file.
 */

#include "pgsentinel.h"
#include "postgres.h"
#include "fmgr.h"
#include "access/xact.h"
#include "lib/stringinfo.h"
#include "pgstat.h"
#include "executor/spi.h"
#include "postmaster/bgworker.h"
#include "storage/ipc.h"
#include "storage/latch.h"
#include "storage/proc.h"
#include "utils/guc.h"
#include "utils/snapmgr.h"
#include "miscadmin.h"
#include "storage/spin.h"
#include "utils/date.h"
#include "utils/builtins.h"
#include "utils/memutils.h"
#include "funcapi.h"
#include "optimizer/planner.h"
#include "storage/shm_toc.h"
#include "access/twophase.h"
#include "parser/analyze.h"
#include "parser/scansup.h"
#include "access/hash.h"
#include "commands/extension.h"
#include "catalog/namespace.h"
#include "catalog/pg_authid.h"
#include "utils/acl.h"
/*
 * Headers for the sampling path.  Rather than re-implementing the bodies of
 * pg_stat_get_activity() and pg_blocking_pids() inside the extension (which
 * would tie us to whatever BackendStatusArray / lock-manager layout the
 * targeted PostgreSQL happens to have), we call those two functions directly
 * through the fmgr and build the sampler logic around the values they return.
 * These headers provide what that needs: fmgr OIDs, a standalone ExprContext
 * to receive a set-returning function's tuplestore, tuple-slot access to read
 * the returned rows, array deconstruction for pg_blocking_pids()'s int[]
 * result, and the syscache lookups that turn datid/usesysid into names.
 */
#include "executor/executor.h"
#include "executor/tuptable.h"
#include "utils/tuplestore.h"
#include "utils/array.h"
#include "utils/fmgroids.h"
#include "catalog/pg_type.h"
#include "commands/dbcommands.h"

/* Handle privilege checking across PostgreSQL versions */
#if PG_VERSION_NUM >= 150000
	#define IS_ALLOWED_ROLE(userid) has_privs_of_role(userid, ROLE_PG_READ_ALL_STATS)
#elif PG_VERSION_NUM >= 140000
	#define IS_ALLOWED_ROLE(userid) is_member_of_role(userid, ROLE_PG_READ_ALL_STATS)
#else
	#define IS_ALLOWED_ROLE(userid) is_member_of_role(userid, DEFAULT_ROLE_READ_ALL_STATS)
#endif

PG_MODULE_MAGIC;
PG_FUNCTION_INFO_V1(pg_active_session_history);
PG_FUNCTION_INFO_V1(pg_stat_statements_history);

#define PG_ACTIVE_SESSION_HISTORY_COLS        28
#define PG_STAT_STATEMENTS_HISTORY_COLS       24
#define EXTENSION_NAME "pgsentinel"

/* Entry point of library loading */
void _PG_init(void);
void _PG_fini(void);
PGDLLEXPORT void pgsentinel_main(Datum);

/* Signal handling */
static volatile sig_atomic_t got_sigterm = false;
static volatile sig_atomic_t got_sighup = false;

/* Saved hook values in case of unload */
static shmem_startup_hook_type ash_prev_shmem_startup_hook = NULL;
#if (PG_VERSION_NUM >= 150000)
static shmem_request_hook_type ash_prev_shmem_request_hook = NULL;
#endif

/* Our hooks */
static void ash_shmem_startup(void);
static void ash_shmem_shutdown(int code, Datum arg);
static void ash_shmem_request(void);

/* GUC variables */
static int ash_sampling_period = 1;
static int ash_max_entries = 1000;
static int pgssh_max_entries = 10000;
static bool pgssh_enable = false;
static bool ash_track_idle_trans = false;
static int ash_restart_wait_time = 2;
static char *pgsentinelDbName = "postgres";

/* Worker name */
static char *worker_name = "pgsentinel";


static const char * const pg_stat_statements_query=
#if PG_VERSION_NUM < 130000
"select userid, dbid, queryid, calls, total_time, rows, shared_blks_hit, \
 shared_blks_read, shared_blks_dirtied, shared_blks_written, local_blks_hit, \
 local_blks_read, local_blks_dirtied, local_blks_written, temp_blks_read, \
 temp_blks_written, blk_read_time, blk_write_time from pg_stat_statements \
 where queryid in  (select queryid from pg_active_session_history  \
 where ash_time in (select ash_time from pg_active_session_history  \
 order by ash_time desc limit 1))";
#else
"select userid, dbid, queryid, calls, total_exec_time, rows, shared_blks_hit, \
 shared_blks_read, shared_blks_dirtied, shared_blks_written, local_blks_hit, \
 local_blks_read, local_blks_dirtied, local_blks_written, temp_blks_read, \
 temp_blks_written, blk_read_time, blk_write_time, \
 plans, total_plan_time, wal_records, wal_fpi, wal_bytes \
 from pg_stat_statements \
 where queryid in  (select queryid from pg_active_session_history  \
 where ash_time in (select ash_time from pg_active_session_history  \
 order by ash_time desc limit 1))";
#endif

static void pg_active_session_history_internal(FunctionCallInfo fcinfo);
static void pg_stat_statements_history_internal(FunctionCallInfo fcinfo);

procEntry *ProcEntryArray = NULL;
post_parse_analyze_hook_type prev_post_parse_analyze_hook = NULL;

/* ash entry */
typedef struct ashEntry
{
	int pid;
#if PG_VERSION_NUM >= 130000
	int leader_pid;
#endif
	int client_port;
	uint64 queryid;
	TimestampTz ash_time;
	Oid datid;
	Oid usesysid;
	char *usename;
	char *datname;
	char *application_name;
	char *wait_event_type;
	char *wait_event;
	char *state;
	char *blocker_state;
	char *client_hostname;
	int blockers;
	int blockerpid;
	char *top_level_query;
	char *query;
	char *cmdtype;
	char *backend_type;
	char *client_addr;
	TransactionId backend_xmin;
	TransactionId backend_xid;
	TimestampTz backend_start;
	TimestampTz xact_start;
	TimestampTz query_start;
	TimestampTz state_change;
} ashEntry;

/* pg_stat_statement_history entry */
typedef struct pgsshEntry
{
	TimestampTz ash_time;
	Oid userid;
	Oid dbid;
	uint64 queryid;
	int64 calls;
	double total_time;
	int64 rows;
	int64 shared_blks_hit;
	int64 shared_blks_read;
	int64 shared_blks_dirtied;
	int64 shared_blks_written;
	int64 local_blks_hit;
	int64 local_blks_read;
	int64 local_blks_dirtied;
	int64 local_blks_written;
	int64 temp_blks_read;
	int64 temp_blks_written;
	double blk_read_time;
	double blk_write_time;
#if PG_VERSION_NUM >= 130000
	int64 plans;
	double total_plan_time;
	int64 wal_records;
	int64 wal_fpi;
	uint64 wal_bytes;
#endif
} pgsshEntry;

/* counters */
typedef struct intEntry
{
	int inserted;
	int pgsshinserted;
} intEntry;

/* For shared memory */
static char *AshEntryUsenameBuffer = NULL;
static char *AshEntryDatnameBuffer = NULL;
static char *AshEntryAppnameBuffer = NULL;
static char *AshEntryWaitEventTypeBuffer = NULL;
static char *AshEntryWaitEventBuffer = NULL;
static char *AshEntryClientHostnameBuffer = NULL;
static char *AshEntryTopLevelQueryBuffer = NULL;
static char *AshEntryQueryBuffer = NULL;
static char *AshEntryCmdTypeBuffer = NULL;
static char *AshEntryBackendTypeBuffer = NULL;
static char *AshEntryStateBuffer = NULL;
static char *AshEntryBlockerStateBuffer = NULL;
static char *AshEntryClientaddrBuffer = NULL;
static ashEntry *AshEntryArray = NULL;
static intEntry *IntEntryArray = NULL;
static pgsshEntry *PgsshEntryArray = NULL;
static char *ProcQueryBuffer = NULL;
static char *ProcCmdTypeBuffer = NULL;

/* Estimate amount of shared memory needed */
static Size ash_entry_memsize(void);

/* check extension is loaded/present */
static bool PgSentinelHasBeenLoaded(void);

/* store ash entry */
static void ash_entry_store(TimestampTz ash_time,const int pid,
#if PG_VERSION_NUM >= 130000
							int leader_pid,
#endif
							const char *usename, const int client_port,Oid datid,
							const char *datname, const char *application_name,
							const char *client_addr, TransactionId backend_xmin,
							TimestampTz backend_start, TimestampTz xact_start,
							TimestampTz query_start, TimestampTz state_change,
							const char *wait_event_type, const char *wait_event,
							const char *state, const char *client_hostname,
							const char *query, const char *backend_type,
							Oid usesysid, TransactionId backend_xid,
							int blockers, int blockerpid,
							const char *blocker_state, uint64 queryid,
							const char *gpi_query, const char *cmdtype);

/* prepare store ash */
static void ash_prepare_store(TimestampTz ash_time,const int pid,
#if PG_VERSION_NUM >= 130000
								int leader_pid,
#endif
								const char* usename,const int client_port,
								Oid datid, const char *datname,
								const char *application_name,
								const char *client_addr,
								TransactionId backend_xmin,
								TimestampTz backend_start,
								TimestampTz xact_start, TimestampTz query_start,
								TimestampTz state_change,
								const char *wait_event_type,
								const char *wait_event, const char *state,
								const char *client_hostname, const char *query,
								const char *backend_type, Oid usesysid,
								TransactionId backend_xid, int blockers,
								int blockerpid, const char *blocker_state,
								uint64 queryid, const char *gpi_query,
								const char *cmdtype);

/* Estimate amount of shared memory needed for ash entry */
static Size
ash_entry_memsize(void)
{
	Size            size;

	/* AshEntryArray */
	size = mul_size(sizeof(ashEntry), ash_max_entries);
	/* AshEntryUsenameBuffer */
	size = add_size(size, mul_size(NAMEDATALEN, ash_max_entries));
	/* AshEntryDatnameBuffer */
	size = add_size(size, mul_size(NAMEDATALEN, ash_max_entries));
	/* AshEntryAppnameBuffer */
	size = add_size(size, mul_size(NAMEDATALEN, ash_max_entries));
	/* AshEntryClientaddrBuffer */
	size = add_size(size, mul_size(NAMEDATALEN, ash_max_entries));
	/* AshEntryWaitEventTypeBuffer */
	size = add_size(size, mul_size(NAMEDATALEN, ash_max_entries));
	/* AshEntryWaitEventBuffer */
	size = add_size(size, mul_size(NAMEDATALEN, ash_max_entries));
	/* AshEntryStateBuffer */
	size = add_size(size, mul_size(NAMEDATALEN, ash_max_entries));
	/* AshEntryClientHostnameBuffer */
	size = add_size(size, mul_size(NAMEDATALEN, ash_max_entries));
	/* AshEntryQueryBuffer */
	size = add_size(size, mul_size(pgstat_track_activity_query_size,
															ash_max_entries));
	/* AshEntryCmdTypeBuffer */
	size = add_size(size, mul_size(NAMEDATALEN, ash_max_entries));
	/* AshEntryTopLevelQueryBuffer */
	size = add_size(size, mul_size(pgstat_track_activity_query_size,
															ash_max_entries));
	/* AshEntryBackendTypeBuffer */
	size = add_size(size, mul_size(NAMEDATALEN, ash_max_entries));
	/* AshEntryBlockerStateBuffer */
	size = add_size(size, mul_size(NAMEDATALEN, ash_max_entries));

	return size;
}

/* Estimate amount of shared memory needed for int entry*/
static Size
int_entry_memsize(void)
{
	Size            size;
	/* IntEntryArray */
	size = mul_size(sizeof(intEntry), 1);
	return size;
}

/* Estimate amount of shared memory needed for pgssh entry*/
static Size
pgssh_entry_memsize(void)
{
	Size            size;
	/* PgsshEntryArray */
	size = mul_size(sizeof(pgsshEntry), pgssh_max_entries);
	return size;
}

static void
ash_shmem_startup(void)
{

	Size size;
	bool   found;
	char   *buffer;
	int    i;

	if (ash_prev_shmem_startup_hook)
		ash_prev_shmem_startup_hook();

	size = mul_size(sizeof(ashEntry), ash_max_entries);
	AshEntryArray = (ashEntry *) ShmemInitStruct("Ash Entry Array", size,
																		&found);

	if (!found)
		MemSet(AshEntryArray, 0, size);

	size = mul_size(sizeof(intEntry), 1);
	IntEntryArray = (intEntry *) ShmemInitStruct("int Entry Array", size,
																		&found);

	if (!found)
	{
		MemSet(IntEntryArray, 0, size);
		IntEntryArray[0].inserted=0;
		IntEntryArray[0].pgsshinserted=0;
	}

	if (pgssh_enable)
	{
		size = mul_size(sizeof(pgsshEntry), pgssh_max_entries);
		PgsshEntryArray = (pgsshEntry *) ShmemInitStruct("pgssh Entry Array",
																size, &found);

		if (!found)
			MemSet(PgsshEntryArray, 0, size);
	}

	size = mul_size(sizeof(procEntry), get_max_procs_count());
	ProcEntryArray = (procEntry *) ShmemInitStruct("Get_parsedinfo Proc Entry",
																size, &found);

	if (!found)
	{
		MemSet(ProcEntryArray, 0, size);
	}

	size = mul_size(pgstat_track_activity_query_size, get_max_procs_count());
	ProcQueryBuffer = (char *) ShmemInitStruct("Proc Query Buffer", size,
																	&found);

	if (!found)
	{
		MemSet(ProcQueryBuffer, 0, size);

		/* Initialize pointers. */
		buffer = ProcQueryBuffer;
		for (i = 0; i < get_max_procs_count(); i++)
		{
			ProcEntryArray[i].query= buffer;
			buffer += pgstat_track_activity_query_size;
		}
	}

	size = mul_size(NAMEDATALEN, get_max_procs_count());
	ProcCmdTypeBuffer = (char *) ShmemInitStruct("Proc CmdType Buffer", size,
																		&found);

	if (!found)
	{
		MemSet(ProcCmdTypeBuffer, 0, size);

		/* Initialize pointers. */
		buffer = ProcCmdTypeBuffer;
		for (i = 0; i < get_max_procs_count(); i++)
		{
			ProcEntryArray[i].cmdtype= buffer;
			buffer += NAMEDATALEN;
		}
	}

	size = mul_size(NAMEDATALEN, ash_max_entries);
	AshEntryUsenameBuffer = (char *)
		ShmemInitStruct("Ash Entry useName Buffer", size, &found);

	if (!found)
	{
		MemSet(AshEntryUsenameBuffer, 0, size);

		/* Initialize usename pointers. */
		buffer = AshEntryUsenameBuffer;
		for (i = 0; i < ash_max_entries; i++)
		{
			AshEntryArray[i].usename = buffer;
			buffer += NAMEDATALEN;
		}
	}


	size = mul_size(NAMEDATALEN, ash_max_entries);
	AshEntryDatnameBuffer = (char *)
		ShmemInitStruct("Ash Entry DatName Buffer", size, &found);

	if (!found)
	{
		MemSet(AshEntryDatnameBuffer, 0, size);

		/* Initialize Datname pointers. */
		buffer = AshEntryDatnameBuffer;
		for (i = 0; i < ash_max_entries; i++)
		{
			AshEntryArray[i].datname = buffer;
			buffer += NAMEDATALEN;
		}
	}


	size = mul_size(NAMEDATALEN, ash_max_entries);
	AshEntryAppnameBuffer = (char *)
		ShmemInitStruct("Ash Entry AppName Buffer", size, &found);

	if (!found)
	{
		MemSet(AshEntryAppnameBuffer, 0, size);

		/* Initialize Appname pointers. */
		buffer = AshEntryAppnameBuffer;
		for (i = 0; i < ash_max_entries; i++)
		{
			AshEntryArray[i].application_name = buffer;
			buffer += NAMEDATALEN;
		}
	}

	size = mul_size(NAMEDATALEN, ash_max_entries);
	AshEntryClientaddrBuffer = (char *)
		ShmemInitStruct("Ash Entry Client Addr Buffer", size, &found);

	if (!found)
	{
		MemSet(AshEntryClientaddrBuffer, 0, size);

		/* Initialize Client Addr pointers. */
		buffer = AshEntryClientaddrBuffer;
		for (i = 0; i < ash_max_entries; i++)
		{
			AshEntryArray[i].client_addr = buffer;
			buffer += NAMEDATALEN;
		}
	}

	size = mul_size(NAMEDATALEN, ash_max_entries);
	AshEntryWaitEventTypeBuffer = (char *)
		ShmemInitStruct("Ash Entry Wait event type Buffer", size, &found);

	if (!found)
	{
		MemSet(AshEntryWaitEventTypeBuffer, 0, size);

		/* Initialize wait event type pointers. */
		buffer = AshEntryWaitEventTypeBuffer;
		for (i = 0; i < ash_max_entries; i++)
		{
			AshEntryArray[i].wait_event_type = buffer;
			buffer += NAMEDATALEN;
		}
	}

	size = mul_size(NAMEDATALEN, ash_max_entries);
	AshEntryWaitEventBuffer = (char *)
		ShmemInitStruct("Ash Entry Wait Event Buffer", size, &found);

	if (!found)
	{
		MemSet(AshEntryWaitEventBuffer, 0, size);

		/* Initialize wait event pointers. */
		buffer = AshEntryWaitEventBuffer;
		for (i = 0; i < ash_max_entries; i++)
		{
			AshEntryArray[i].wait_event = buffer;
			buffer += NAMEDATALEN;
		}
	}


	size = mul_size(NAMEDATALEN, ash_max_entries);
	AshEntryStateBuffer = (char *)
		ShmemInitStruct("Ash Entry State Buffer", size, &found);

	if (!found)
	{
		MemSet(AshEntryStateBuffer, 0, size);

		/* Initialize state pointers. */
		buffer = AshEntryStateBuffer;
		for (i = 0; i < ash_max_entries; i++)
		{
			AshEntryArray[i].state = buffer;
			buffer += NAMEDATALEN;
		}
	}

	size = mul_size(NAMEDATALEN, ash_max_entries);
	AshEntryClientHostnameBuffer = (char *)
		ShmemInitStruct("Ash Entry Client Hostname Buffer", size, &found);

	if (!found)
	{
		MemSet(AshEntryClientHostnameBuffer, 0, size);

		/* Initialize client hostname pointers. */
		buffer = AshEntryClientHostnameBuffer;
		for (i = 0; i < ash_max_entries; i++)
		{
			AshEntryArray[i].client_hostname = buffer;
			buffer += NAMEDATALEN;
		}
	}

	size = mul_size(pgstat_track_activity_query_size, ash_max_entries);
	AshEntryTopLevelQueryBuffer = (char *)
		ShmemInitStruct("Ash Entry Top Level Query Buffer", size, &found);

	if (!found)
	{
		MemSet(AshEntryTopLevelQueryBuffer, 0, size);

		/* Initialize top level query pointers. */
		buffer = AshEntryTopLevelQueryBuffer;
		for (i = 0; i < ash_max_entries; i++)
		{
			AshEntryArray[i].top_level_query = buffer;
			buffer += pgstat_track_activity_query_size;
		}
	}

	size = mul_size(pgstat_track_activity_query_size, ash_max_entries);
	AshEntryQueryBuffer = (char *)
		ShmemInitStruct("Ash Entry Query Buffer", size, &found);

	if (!found)
	{
		MemSet(AshEntryQueryBuffer, 0, size);

		/* Initialize query pointers. */
		buffer = AshEntryQueryBuffer;
		for (i = 0; i < ash_max_entries; i++)
		{
			AshEntryArray[i].query = buffer;
			buffer += pgstat_track_activity_query_size;
		}
	}

	size = mul_size(NAMEDATALEN, ash_max_entries);
	AshEntryCmdTypeBuffer = (char *)
		ShmemInitStruct("Ash Entry CmdType Buffer", size, &found);

	if (!found)
	{
		MemSet(AshEntryCmdTypeBuffer, 0, size);

		/* Initialize cmdtype pointers. */
		buffer = AshEntryCmdTypeBuffer;
		for (i = 0; i < ash_max_entries; i++)
		{
			AshEntryArray[i].cmdtype = buffer;
			buffer += NAMEDATALEN;
		}
	}


	size = mul_size(NAMEDATALEN, ash_max_entries);
	AshEntryBackendTypeBuffer = (char *)
		ShmemInitStruct("Ash Entry Backend Type Buffer", size, &found);

	if (!found)
	{
		MemSet(AshEntryBackendTypeBuffer, 0, size);

		/* Initialize backend type pointers. */
		buffer = AshEntryBackendTypeBuffer;
		for (i = 0; i < ash_max_entries; i++)
		{
			AshEntryArray[i].backend_type = buffer;
			buffer += NAMEDATALEN;
		}
	}

	size = mul_size(NAMEDATALEN, ash_max_entries);
	AshEntryBlockerStateBuffer = (char *)
		ShmemInitStruct("Ash Entry Blocker State Buffer", size, &found);

	if (!found)
	{
		MemSet(AshEntryBlockerStateBuffer, 0, size);

		/* Initialize state pointers. */
		buffer = AshEntryBlockerStateBuffer;
		for (i = 0; i < ash_max_entries; i++)
		{
			AshEntryArray[i].blocker_state = buffer;
			buffer += NAMEDATALEN;
		}
	}

	/*
	 * set up a shmem exit hook to do whatever useful (dump to disk later on?).
	 */
	if (!IsUnderPostmaster)
		on_shmem_exit(ash_shmem_shutdown, (Datum) 0);


	if (found)
		return;
}

static void
ash_shmem_shutdown(int code, Datum arg)
{
	/* Don't try to dump during a crash. */
	if (code)
		return;

	/* Safety check ... shouldn't get here unless shmem is set up. */
	if (!AshEntryArray)
		return;

	/* dump to disk ?*/
	/* This is the place */
}


static void
pgsentinel_sigterm(SIGNAL_ARGS)
{
	int save_errno = errno;
	got_sigterm = true;
#if PG_VERSION_NUM >= 100000
	SetLatch(MyLatch);
#else
	if (MyProc)
		SetLatch(&MyProc->procLatch);
#endif
	errno = save_errno;
}

static void
pgsentinel_sighup(SIGNAL_ARGS)
{
	int save_errno = errno;
	got_sighup = true;
#if PG_VERSION_NUM >= 100000
	SetLatch(MyLatch);
#else
	if (MyProc)
		SetLatch(&MyProc->procLatch);
#endif
	errno = save_errno;
}

static void
ash_entry_store(TimestampTz ash_time, const int pid,
#if PG_VERSION_NUM >= 130000
				int leader_pid,
#endif
				const char *usename,
				const int client_port, Oid datid, const char *datname,
				const char *application_name, const char *client_addr,
				TransactionId backend_xmin, TimestampTz backend_start,
				TimestampTz xact_start, TimestampTz query_start,
				TimestampTz state_change, const char *wait_event_type,
				const char *wait_event, const char *state,
				const char *client_hostname, const char *query,
				const char *backend_type, Oid usesysid,
				TransactionId backend_xid, int blockers, int blockerpid,
				const char *blocker_state, uint64 queryid,
				const char *gpi_query, const char *cmdtype)
{
	int inserted;
	inserted=IntEntryArray[0].inserted-1;
	memcpy(AshEntryArray[inserted].usename,usename,Min(strlen(usename)+1,
																NAMEDATALEN-1));
	memcpy(AshEntryArray[inserted].datname,datname,Min(strlen(datname)+1,
																NAMEDATALEN-1));
	memcpy(AshEntryArray[inserted].application_name,application_name,
								Min(strlen(application_name)+1,NAMEDATALEN-1));
	memcpy(AshEntryArray[inserted].wait_event_type,wait_event_type,
								Min(strlen(wait_event_type)+1,NAMEDATALEN-1));
	memcpy(AshEntryArray[inserted].wait_event,wait_event,
								Min(strlen(wait_event)+1,NAMEDATALEN-1));
	memcpy(AshEntryArray[inserted].state,state,Min(strlen(state)+1,
																NAMEDATALEN-1));
	memcpy(AshEntryArray[inserted].blocker_state,blocker_state,
								Min(strlen(blocker_state)+1,NAMEDATALEN-1));
	memcpy(AshEntryArray[inserted].client_hostname,client_hostname,
								Min(strlen(client_hostname)+1,NAMEDATALEN-1));
	memcpy(AshEntryArray[inserted].top_level_query,query,
					Min((int) strlen(query)+1,pgstat_track_activity_query_size-1));
	memcpy(AshEntryArray[inserted].backend_type,backend_type,
									Min(strlen(backend_type)+1,NAMEDATALEN-1));
	memcpy(AshEntryArray[inserted].client_addr,client_addr,
									Min(strlen(client_addr)+1,NAMEDATALEN-1));
	memcpy(AshEntryArray[inserted].query,gpi_query,Min((int) strlen(gpi_query)+1,
										pgstat_track_activity_query_size-1));
	memcpy(AshEntryArray[inserted].cmdtype,cmdtype,Min((int) strlen(cmdtype)+1,
																NAMEDATALEN-1));
	AshEntryArray[inserted].client_port=client_port;
	AshEntryArray[inserted].datid=datid;
	AshEntryArray[inserted].usesysid=usesysid;
	AshEntryArray[inserted].pid=pid;
#if PG_VERSION_NUM >= 130000
	AshEntryArray[inserted].leader_pid=leader_pid;
#endif
	AshEntryArray[inserted].backend_xmin=backend_xmin;
	AshEntryArray[inserted].backend_xid=backend_xid;
	AshEntryArray[inserted].backend_start=backend_start;
	AshEntryArray[inserted].xact_start=xact_start;
	AshEntryArray[inserted].query_start=query_start;
	AshEntryArray[inserted].state_change=state_change;
	AshEntryArray[inserted].ash_time=ash_time;
	AshEntryArray[inserted].blockers=blockers;
	AshEntryArray[inserted].blockerpid=blockerpid;
	AshEntryArray[inserted].queryid=queryid;
}

static void
ash_prepare_store(TimestampTz ash_time, const int pid,
#if PG_VERSION_NUM >= 130000
					int leader_pid,
#endif
					const char* usename,
					const int client_port, Oid datid, const char *datname,
					const char *application_name, const char *client_addr,
					TransactionId backend_xmin, TimestampTz backend_start,
					TimestampTz xact_start, TimestampTz query_start,
					TimestampTz state_change, const char *wait_event_type,
					const char *wait_event, const char *state,
					const char *client_hostname, const char *query,
					const char *backend_type, Oid usesysid,
					TransactionId backend_xid, int blockers, int blockerpid,
					const char *blocker_state, uint64 queryid,
					const char *gpi_query, const char *cmdtype)
{
	/* Safety check... */
	if (!AshEntryArray) { return; }

	IntEntryArray[0].inserted=(IntEntryArray[0].inserted % ash_max_entries) + 1;
	ash_entry_store(ash_time, pid,
#if PG_VERSION_NUM >= 130000
					leader_pid,
#endif
					usename, client_port, datid, datname,
					application_name, client_addr,backend_xmin, backend_start,
					xact_start, query_start, state_change, wait_event_type,
					wait_event, state, client_hostname, query, backend_type,
					usesysid, backend_xid, blockers, blockerpid, blocker_state,
					queryid, gpi_query, cmdtype);
}

/*
 * Sampling helpers.
 *
 * These functions never touch the BackendStatusArray or the lock manager's
 * internal structures directly.  Instead they invoke pg_stat_get_activity()
 * and pg_blocking_pids() through the fmgr and work with the values those
 * functions return, so the sampler rides on documented, version-stable
 * interfaces (the columns of pg_stat_activity and an int[] of blocking pids)
 * rather than on a snapshot of core internals copied into the extension.
 */

/* One collected pg_stat_activity row, kept only for the duration of a tick. */
typedef struct ashActivityRow
{
	int				pid;
	int				leader_pid;
	int				client_port;
	Oid				datid;
	Oid				usesysid;
	TransactionId	backend_xid;
	TransactionId	backend_xmin;
	TimestampTz		backend_start;
	TimestampTz		xact_start;
	TimestampTz		query_start;
	TimestampTz		state_change;
	uint64			query_id;
	char		   *application_name;
	char		   *wait_event_type;
	char		   *wait_event;
	char		   *state;
	char		   *client_hostname;
	char		   *client_addr;
	char		   *backend_type;
	char		   *top_level_query;
} ashActivityRow;

/* Resolve a column of pg_stat_get_activity() by name; 0 when not present. */
static int
ash_activity_attno(TupleDesc tupdesc, const char *name)
{
	int			i;

	for (i = 0; i < tupdesc->natts; i++)
	{
		Form_pg_attribute att = TupleDescAttr(tupdesc, i);

		if (!att->attisdropped && strcmp(NameStr(att->attname), name) == 0)
			return att->attnum;
	}
	return 0;
}

/*
 * Insist that a column every supported pg_stat_get_activity() returns was
 * actually found.  Resolving one to 0 means the shape of that function changed
 * under us, and because a missing attribute silently falls back to a default
 * the sampler would keep running while reporting nonsense: a renamed
 * wait_event_type would mark every session as "CPU", and a renamed state would
 * match nothing and quietly collect an empty history.  Refuse to sample on
 * instead, the way the SPI sampler used to fail when its query stopped
 * matching pg_stat_activity.
 *
 * Columns that are genuinely optional across versions (backend_type before 10,
 * leader_pid before 13, query_id before 14) are not checked here; their
 * defaults are the intended behaviour.
 */
static void
ash_require_activity_attno(int attno, const char *name)
{
	if (attno <= 0)
		elog(FATAL,
			 "pgsentinel: pg_stat_get_activity() has no \"%s\" column", name);
}

/* Read a text column, returning def when the attribute is missing or NULL. */
static char *
ash_activity_text(TupleTableSlot *slot, int attno, char *def)
{
	bool		isnull;
	Datum		value;

	if (attno <= 0)
		return def;
	value = slot_getattr(slot, attno, &isnull);
	if (isnull)
		return def;
	return TextDatumGetCString(value);
}

/*
 * Ask PostgreSQL who blocks a pid by calling pg_blocking_pids() and inspecting
 * the array it returns: the element count is the number of blockers and the
 * first element is the pid we surface as "blockerpid".  All of the lock-table
 * analysis stays inside pg_blocking_pids(); we only read its result.
 */
static void
ash_get_blockers(int pid, int *blocker_pid, int *blocker_count)
{
	Datum		result;
	ArrayType  *arr;
	Datum	   *elems;
	bool	   *nulls;
	int			nelems;

	*blocker_pid = 0;
	*blocker_count = 0;

	result = OidFunctionCall1(F_PG_BLOCKING_PIDS, Int32GetDatum(pid));
	arr = DatumGetArrayTypeP(result);
	if (arr == NULL)
		return;

	deconstruct_array(arr, INT4OID, sizeof(int32), true, 'i',
					  &elems, &nulls, &nelems);
	*blocker_count = nelems;
	if (nelems > 0 && !nulls[0])
		*blocker_pid = DatumGetInt32(elems[0]);
}

/* Find the reported state of a pid among the rows collected this tick. */
static char *
ash_state_of_pid(ashActivityRow *rows, int nrows, int pid)
{
	int			i;

	if (pid == 0)
		return "";
	for (i = 0; i < nrows; i++)
		if (rows[i].pid == pid)
			return rows[i].state;
	return "";
}

/*
 * Look up the parsed query/cmdtype/queryid the extension recorded for a pid in
 * its own ProcEntryArray (populated by the post_parse_analyze hook).  This is
 * extension-owned data, indexed the same way get_parsedinfo() indexes it.
 */
static procEntry *
ash_proc_entry_of_pid(int pid)
{
	int			i;

	for (i = 0; i < (int) ProcGlobal->allProcCount; i++)
		if (ProcGlobal->allProcs[i].pid == pid)
			return &ProcEntryArray[i];
	return NULL;
}

/*
 * Invoke pg_stat_get_activity(NULL) directly (no SPI, no SQL text) and return
 * its materialized tuplestore together with the result descriptor.  The
 * caller must eventually FreeExprContext(*econtext).
 */
static Tuplestorestate *
ash_run_pg_stat_get_activity(ExprContext **econtext, TupleDesc *tupdesc)
{
	FmgrInfo		flinfo;
	ReturnSetInfo	rsinfo;

	*econtext = CreateStandaloneExprContext();

	fmgr_info(F_PG_STAT_GET_ACTIVITY, &flinfo);

	memset(&rsinfo, 0, sizeof(rsinfo));
	rsinfo.type = T_ReturnSetInfo;
	rsinfo.econtext = *econtext;
	rsinfo.expectedDesc = NULL;
	rsinfo.allowedModes = SFRM_Materialize;
	rsinfo.returnMode = SFRM_Materialize;
	rsinfo.setResult = NULL;
	rsinfo.setDesc = NULL;

#if PG_VERSION_NUM >= 120000
	{
		LOCAL_FCINFO(fcinfo, 1);

		InitFunctionCallInfoData(*fcinfo, &flinfo, 1, InvalidOid, NULL,
								 (Node *) &rsinfo);
		fcinfo->args[0].value = (Datum) 0;
		fcinfo->args[0].isnull = true;	/* NULL pid -> every backend */
		(void) FunctionCallInvoke(fcinfo);
	}
#else
	{
		FunctionCallInfoData fcinfo;

		InitFunctionCallInfoData(fcinfo, &flinfo, 1, InvalidOid, NULL,
								 (Node *) &rsinfo);
		fcinfo.arg[0] = (Datum) 0;
		fcinfo.argnull[0] = true;
		(void) FunctionCallInvoke(&fcinfo);
	}
#endif

	*tupdesc = rsinfo.setDesc;
	return rsinfo.setResult;
}

/*
 * Collect one ASH sample by walking what pg_stat_get_activity() returns and,
 * for each interesting session, computing its blockers with pg_blocking_pids()
 * and attaching the parsed query info the extension already tracks.  The shape
 * of what we store matches the old SQL sampler so pg_active_session_history is
 * unchanged.
 */
static void
ash_collect_sample(TimestampTz ash_time, bool track_idle, bool *gotactives)
{
	ExprContext	   *econtext = NULL;
	Tuplestorestate *tupstore;
	TupleDesc		tupdesc = NULL;
	TupleTableSlot *slot;
	int				my_pid = MyProcPid;
	ashActivityRow *rows;
	int				nrows = 0;
	int				maxrows = 64;
	int				r;
	int				a_datid,
					a_pid,
					a_usesysid,
					a_appname,
					a_state,
					a_query,
					a_wetype,
					a_we,
					a_xact_start,
					a_query_start,
					a_backend_start,
					a_state_change,
					a_client_addr,
					a_client_hostname,
					a_client_port,
					a_backend_xid,
					a_backend_xmin,
					a_backend_type,
					a_leader_pid,
					a_query_id;

	tupstore = ash_run_pg_stat_get_activity(&econtext, &tupdesc);
	if (tupstore == NULL || tupdesc == NULL)
	{
		if (econtext != NULL)
			FreeExprContext(econtext, true);
		return;
	}

	a_datid = ash_activity_attno(tupdesc, "datid");
	a_pid = ash_activity_attno(tupdesc, "pid");
	a_usesysid = ash_activity_attno(tupdesc, "usesysid");
	a_appname = ash_activity_attno(tupdesc, "application_name");
	a_state = ash_activity_attno(tupdesc, "state");
	a_query = ash_activity_attno(tupdesc, "query");
	a_wetype = ash_activity_attno(tupdesc, "wait_event_type");
	a_we = ash_activity_attno(tupdesc, "wait_event");
	a_xact_start = ash_activity_attno(tupdesc, "xact_start");
	a_query_start = ash_activity_attno(tupdesc, "query_start");
	a_backend_start = ash_activity_attno(tupdesc, "backend_start");
	a_state_change = ash_activity_attno(tupdesc, "state_change");
	a_client_addr = ash_activity_attno(tupdesc, "client_addr");
	a_client_hostname = ash_activity_attno(tupdesc, "client_hostname");
	a_client_port = ash_activity_attno(tupdesc, "client_port");
	a_backend_xid = ash_activity_attno(tupdesc, "backend_xid");
	a_backend_xmin = ash_activity_attno(tupdesc, "backend_xmin");
	a_backend_type = ash_activity_attno(tupdesc, "backend_type");
	a_leader_pid = ash_activity_attno(tupdesc, "leader_pid");	/* >= 13 */
	a_query_id = ash_activity_attno(tupdesc, "query_id");		/* >= 14 */

	/* Everything below is expected on every version we build against. */
	ash_require_activity_attno(a_datid, "datid");
	ash_require_activity_attno(a_pid, "pid");
	ash_require_activity_attno(a_usesysid, "usesysid");
	ash_require_activity_attno(a_appname, "application_name");
	ash_require_activity_attno(a_state, "state");
	ash_require_activity_attno(a_query, "query");
	ash_require_activity_attno(a_wetype, "wait_event_type");
	ash_require_activity_attno(a_we, "wait_event");
	ash_require_activity_attno(a_xact_start, "xact_start");
	ash_require_activity_attno(a_query_start, "query_start");
	ash_require_activity_attno(a_backend_start, "backend_start");
	ash_require_activity_attno(a_state_change, "state_change");
	ash_require_activity_attno(a_client_addr, "client_addr");
	ash_require_activity_attno(a_client_hostname, "client_hostname");
	ash_require_activity_attno(a_client_port, "client_port");
	ash_require_activity_attno(a_backend_xid, "backend_xid");
	ash_require_activity_attno(a_backend_xmin, "backend_xmin");
#if PG_VERSION_NUM >= 100000
	ash_require_activity_attno(a_backend_type, "backend_type");
#endif

#if PG_VERSION_NUM >= 120000
	slot = MakeSingleTupleTableSlot(tupdesc, &TTSOpsMinimalTuple);
#else
	slot = MakeSingleTupleTableSlot(tupdesc);
#endif

	rows = (ashActivityRow *) palloc(sizeof(ashActivityRow) * maxrows);

	/* Pass 1: pull every backend into a transient array. */
	while (tuplestore_gettupleslot(tupstore, true, false, slot))
	{
		ashActivityRow *row;
		bool		isnull;
		Datum		value;

		if (nrows >= maxrows)
		{
			maxrows *= 2;
			rows = (ashActivityRow *) repalloc(rows,
											   sizeof(ashActivityRow) * maxrows);
		}
		row = &rows[nrows++];
		memset(row, 0, sizeof(*row));

		if (a_pid > 0)
		{
			value = slot_getattr(slot, a_pid, &isnull);
			row->pid = isnull ? 0 : DatumGetInt32(value);
		}
		if (a_leader_pid > 0)
		{
			value = slot_getattr(slot, a_leader_pid, &isnull);
			row->leader_pid = isnull ? 0 : DatumGetInt32(value);
		}
		if (a_client_port > 0)
		{
			value = slot_getattr(slot, a_client_port, &isnull);
			row->client_port = isnull ? 0 : DatumGetInt32(value);
		}
		if (a_datid > 0)
		{
			value = slot_getattr(slot, a_datid, &isnull);
			row->datid = isnull ? InvalidOid : DatumGetObjectId(value);
		}
		if (a_usesysid > 0)
		{
			value = slot_getattr(slot, a_usesysid, &isnull);
			row->usesysid = isnull ? InvalidOid : DatumGetObjectId(value);
		}
		if (a_backend_xid > 0)
		{
			value = slot_getattr(slot, a_backend_xid, &isnull);
			row->backend_xid = isnull ? InvalidTransactionId
				: DatumGetTransactionId(value);
		}
		if (a_backend_xmin > 0)
		{
			value = slot_getattr(slot, a_backend_xmin, &isnull);
			row->backend_xmin = isnull ? InvalidTransactionId
				: DatumGetTransactionId(value);
		}
		if (a_backend_start > 0)
		{
			value = slot_getattr(slot, a_backend_start, &isnull);
			row->backend_start = isnull ? 0 : DatumGetTimestampTz(value);
		}
		if (a_xact_start > 0)
		{
			value = slot_getattr(slot, a_xact_start, &isnull);
			row->xact_start = isnull ? 0 : DatumGetTimestampTz(value);
		}
		if (a_query_start > 0)
		{
			value = slot_getattr(slot, a_query_start, &isnull);
			row->query_start = isnull ? 0 : DatumGetTimestampTz(value);
		}
		if (a_state_change > 0)
		{
			value = slot_getattr(slot, a_state_change, &isnull);
			row->state_change = isnull ? 0 : DatumGetTimestampTz(value);
		}
		if (a_query_id > 0)
		{
			value = slot_getattr(slot, a_query_id, &isnull);
			row->query_id = isnull ? 0 : (uint64) DatumGetInt64(value);
		}

		row->application_name = ash_activity_text(slot, a_appname, "");
		row->state = ash_activity_text(slot, a_state, "");
		row->top_level_query = ash_activity_text(slot, a_query, "");
		row->wait_event_type = ash_activity_text(slot, a_wetype, "CPU");
		row->wait_event = ash_activity_text(slot, a_we, "CPU");
		row->client_hostname = ash_activity_text(slot, a_client_hostname, "");
		row->backend_type = ash_activity_text(slot, a_backend_type, "");

		/* client_addr is inet; render it via the type's own output function. */
		row->client_addr = "";
		if (a_client_addr > 0)
		{
			value = slot_getattr(slot, a_client_addr, &isnull);
			if (!isnull)
				row->client_addr =
					DatumGetCString(OidFunctionCall1(F_INET_OUT, value));
		}
	}

	/* Pass 2: keep the sessions the old WHERE clause would have kept. */
	for (r = 0; r < nrows; r++)
	{
		ashActivityRow *row = &rows[r];
		bool		wanted;
		int			blocker_pid;
		int			blocker_count;
		char	   *blocker_state;
		char	   *datname;
		char	   *usename;
		procEntry  *pe;
		const char *gpi_query = "";
		const char *cmdtype = "";
		uint64		queryid;

		if (row->pid <= 0 || row->pid == my_pid)
			continue;

		wanted = (strcmp(row->state, "active") == 0) ||
			(track_idle && strcmp(row->state, "idle in transaction") == 0);
		if (!wanted)
			continue;

		ash_get_blockers(row->pid, &blocker_pid, &blocker_count);
		blocker_state = ash_state_of_pid(rows, nrows, blocker_pid);

		pe = ash_proc_entry_of_pid(row->pid);
		queryid = (pe != NULL) ? pe->queryid : 0;
		if (row->query_id != 0)
			queryid = row->query_id;
		if (pe != NULL)
		{
			if (pe->query != NULL && pe->query[0] != '\0')
				gpi_query = pe->query;
			if (pe->cmdtype != NULL && pe->cmdtype[0] != '\0')
				cmdtype = pe->cmdtype;
		}

		datname = OidIsValid(row->datid) ? get_database_name(row->datid) : NULL;
		usename = OidIsValid(row->usesysid)
			? GetUserNameFromId(row->usesysid, true) : NULL;

		*gotactives = true;

		ash_prepare_store(ash_time,
						  row->pid,
#if PG_VERSION_NUM >= 130000
						  row->leader_pid,
#endif
						  usename ? usename : "",
						  row->client_port,
						  row->datid,
						  datname ? datname : "",
						  row->application_name,
						  row->client_addr,
						  row->backend_xmin,
						  row->backend_start,
						  row->xact_start,
						  row->query_start,
						  row->state_change,
						  row->wait_event_type,
						  row->wait_event,
						  row->state,
						  row->client_hostname,
						  row->top_level_query,
						  row->backend_type,
						  row->usesysid,
						  row->backend_xid,
						  blocker_count,
						  blocker_pid,
						  blocker_state,
						  queryid,
						  gpi_query,
						  cmdtype);
	}

	ExecDropSingleTupleTableSlot(slot);
	FreeExprContext(econtext, true);
}

void
pgsentinel_main(Datum main_arg)
{
	MemoryContext pgsentinel_loop_context;
	MemoryContext saved_context;

	ereport(LOG, (errmsg("starting bgworker pgsentinel")));

	/* Register functions for SIGTERM/SIGHUP management */
	pqsignal(SIGHUP, pgsentinel_sighup);
	pqsignal(SIGINT, SIG_IGN);
	pqsignal(SIGTERM, pgsentinel_sigterm);

	/* We're now ready to receive signals */
	BackgroundWorkerUnblockSignals();

	/* Connect to a database */
#if (PG_VERSION_NUM < 110000)
	BackgroundWorkerInitializeConnection(pgsentinelDbName, NULL);
#else
	BackgroundWorkerInitializeConnection(pgsentinelDbName, NULL, 0);
#endif

	pgsentinel_loop_context = AllocSetContextCreate(TopMemoryContext,
													"pgsentinel loop context",
													ALLOCSET_DEFAULT_SIZES);

	saved_context = MemoryContextSwitchTo(pgsentinel_loop_context);

	while (!got_sigterm)
	{
		int rc, ret;
		uint64 i;
		bool gotactives;
		TimestampTz ash_time;
		gotactives=false; 

letswait:
		/* Wait necessary amount of time */
#if PG_VERSION_NUM >= 100000
		rc = WaitLatch(MyLatch, WL_LATCH_SET | WL_TIMEOUT | WL_POSTMASTER_DEATH,
								ash_sampling_period * 1000L,PG_WAIT_EXTENSION);
		ResetLatch(MyLatch);
#else
		rc = WaitLatch(&MyProc->procLatch, WL_LATCH_SET | WL_TIMEOUT |
							WL_POSTMASTER_DEATH, ash_sampling_period * 1000L);
		ResetLatch(&MyProc->procLatch);
#endif

		CHECK_FOR_INTERRUPTS();

		/* Emergency bailout if postmaster has died */
		if (rc & WL_POSTMASTER_DEATH)
			proc_exit(1);

		/* Process signals */
		if (got_sighup)
		{
			/* Process config file */
			got_sighup = false;
			ProcessConfigFile(PGC_SIGHUP);
			ereport(LOG, (errmsg("bgworker pgsentinel signal: processed SIGHUP")));
		}

		if (got_sigterm)
		{
			/* Simply exit */
			ereport(LOG, (errmsg("bgworker pgsentinel signal: processed SIGTERM")));
			proc_exit(0);
		}

		SetCurrentStatementStartTimestamp();
		StartTransactionCommand();
		PushActiveSnapshot(GetTransactionSnapshot());

		if (!PgSentinelHasBeenLoaded()) {
			PopActiveSnapshot();
			CommitTransactionCommand();
			MemoryContextReset(pgsentinel_loop_context);
			goto letswait;
		}

		/*
		 * Sample by calling pg_stat_get_activity() and pg_blocking_pids()
		 * directly instead of running a SQL query over SPI: no statement is
		 * parsed or planned, we just consume what those functions return.
		 */
		pgstat_report_activity(STATE_RUNNING,
							   "pgsentinel: collecting ASH sample");
		ash_time = GetCurrentTimestamp();
		ash_collect_sample(ash_time, ash_track_idle_trans, &gotactives);
		PopActiveSnapshot();
		CommitTransactionCommand();
		pgstat_report_activity(STATE_IDLE, NULL);

		/* pg_stat_statement_history */
		if (gotactives && pgssh_enable)
		{
			SetCurrentStatementStartTimestamp();
			StartTransactionCommand();
			SPI_connect();
			PushActiveSnapshot(GetTransactionSnapshot());
			pgstat_report_activity(STATE_RUNNING, pg_stat_statements_query);

			/* We can now execute queries via SPI */
			ret = SPI_execute(pg_stat_statements_query,true, 0);

			if (ret != SPI_OK_SELECT)
				elog(FATAL, "cannot select from pg_stat_statements: error code %d", ret);

			/* Do some processing */
			if (SPI_processed > 0)
			{
				for (i = 0; i < SPI_processed; i++)
				{
					bool isnull;
					IntEntryArray[0].pgsshinserted=(IntEntryArray[0].pgsshinserted % pgssh_max_entries) + 1;
					PgsshEntryArray[IntEntryArray[0].pgsshinserted-1].ash_time=ash_time;
					PgsshEntryArray[IntEntryArray[0].pgsshinserted-1].userid=DatumGetObjectId(SPI_getbinval(SPI_tuptable->vals[i],SPI_tuptable->tupdesc,1, &isnull));
					PgsshEntryArray[IntEntryArray[0].pgsshinserted-1].dbid=DatumGetObjectId(SPI_getbinval(SPI_tuptable->vals[i],SPI_tuptable->tupdesc,2, &isnull));
					PgsshEntryArray[IntEntryArray[0].pgsshinserted-1].queryid=DatumGetUInt64(SPI_getbinval(SPI_tuptable->vals[i],SPI_tuptable->tupdesc,3, &isnull));
					PgsshEntryArray[IntEntryArray[0].pgsshinserted-1].calls=DatumGetInt64(SPI_getbinval(SPI_tuptable->vals[i],SPI_tuptable->tupdesc,4, &isnull));
					PgsshEntryArray[IntEntryArray[0].pgsshinserted-1].total_time=DatumGetFloat8(SPI_getbinval(SPI_tuptable->vals[i],SPI_tuptable->tupdesc,5, &isnull));
					PgsshEntryArray[IntEntryArray[0].pgsshinserted-1].rows=DatumGetInt64(SPI_getbinval(SPI_tuptable->vals[i],SPI_tuptable->tupdesc,6, &isnull));
					PgsshEntryArray[IntEntryArray[0].pgsshinserted-1].shared_blks_hit=DatumGetInt64(SPI_getbinval(SPI_tuptable->vals[i],SPI_tuptable->tupdesc,7, &isnull));
					PgsshEntryArray[IntEntryArray[0].pgsshinserted-1].shared_blks_read=DatumGetInt64(SPI_getbinval(SPI_tuptable->vals[i],SPI_tuptable->tupdesc,8, &isnull));
					PgsshEntryArray[IntEntryArray[0].pgsshinserted-1].shared_blks_dirtied=DatumGetInt64(SPI_getbinval(SPI_tuptable->vals[i],SPI_tuptable->tupdesc,9, &isnull));
					PgsshEntryArray[IntEntryArray[0].pgsshinserted-1].shared_blks_written=DatumGetInt64(SPI_getbinval(SPI_tuptable->vals[i],SPI_tuptable->tupdesc,10, &isnull));
					PgsshEntryArray[IntEntryArray[0].pgsshinserted-1].local_blks_hit=DatumGetInt64(SPI_getbinval(SPI_tuptable->vals[i],SPI_tuptable->tupdesc,11, &isnull));
					PgsshEntryArray[IntEntryArray[0].pgsshinserted-1].local_blks_read=DatumGetInt64(SPI_getbinval(SPI_tuptable->vals[i],SPI_tuptable->tupdesc,12, &isnull));
					PgsshEntryArray[IntEntryArray[0].pgsshinserted-1].local_blks_dirtied=DatumGetInt64(SPI_getbinval(SPI_tuptable->vals[i],SPI_tuptable->tupdesc,13, &isnull));
					PgsshEntryArray[IntEntryArray[0].pgsshinserted-1].local_blks_written=DatumGetInt64(SPI_getbinval(SPI_tuptable->vals[i],SPI_tuptable->tupdesc,14, &isnull));
					PgsshEntryArray[IntEntryArray[0].pgsshinserted-1].temp_blks_read=DatumGetInt64(SPI_getbinval(SPI_tuptable->vals[i],SPI_tuptable->tupdesc,15, &isnull));
					PgsshEntryArray[IntEntryArray[0].pgsshinserted-1].temp_blks_written=DatumGetInt64(SPI_getbinval(SPI_tuptable->vals[i],SPI_tuptable->tupdesc,16, &isnull));
					PgsshEntryArray[IntEntryArray[0].pgsshinserted-1].blk_read_time=DatumGetFloat8(SPI_getbinval(SPI_tuptable->vals[i],SPI_tuptable->tupdesc,17, &isnull));
					PgsshEntryArray[IntEntryArray[0].pgsshinserted-1].blk_write_time=DatumGetFloat8(SPI_getbinval(SPI_tuptable->vals[i],SPI_tuptable->tupdesc,18, &isnull));
#if PG_VERSION_NUM >= 130000
					PgsshEntryArray[IntEntryArray[0].pgsshinserted-1].plans=DatumGetInt64(SPI_getbinval(SPI_tuptable->vals[i],SPI_tuptable->tupdesc,19, &isnull));
					PgsshEntryArray[IntEntryArray[0].pgsshinserted-1].total_plan_time=DatumGetFloat8(SPI_getbinval(SPI_tuptable->vals[i],SPI_tuptable->tupdesc,20, &isnull));
					PgsshEntryArray[IntEntryArray[0].pgsshinserted-1].wal_records=DatumGetInt64(SPI_getbinval(SPI_tuptable->vals[i],SPI_tuptable->tupdesc,21, &isnull));
					PgsshEntryArray[IntEntryArray[0].pgsshinserted-1].wal_fpi=DatumGetInt64(SPI_getbinval(SPI_tuptable->vals[i],SPI_tuptable->tupdesc,22, &isnull));
					PgsshEntryArray[IntEntryArray[0].pgsshinserted-1].wal_bytes=DatumGetUInt64(SPI_getbinval(SPI_tuptable->vals[i],SPI_tuptable->tupdesc,23, &isnull));
#endif
				}
			}
			SPI_finish();
			PopActiveSnapshot();
			CommitTransactionCommand();
			pgstat_report_activity(STATE_IDLE, NULL);
		}
		MemoryContextReset(pgsentinel_loop_context);
	}
	/* No problems, so clean exit */
	MemoryContextSwitchTo(saved_context);
	proc_exit(0);
}

static void
pgsentinel_load_params(void)
{

	DefineCustomIntVariable("pgsentinel_ash.sampling_period",
							"Duration between each pull (in seconds).",
							NULL,
							&ash_sampling_period,
							1,
							1,
							INT_MAX,
							PGC_SIGHUP,
							0,
							NULL,
							NULL,
							NULL);

	DefineCustomBoolVariable("pgsentinel_ash.track_idle_trans",
	                        "Track session in idle transaction state.",
							NULL,
							&ash_track_idle_trans,
							false,
							PGC_SIGHUP,
							0,
							NULL,
							NULL,
							NULL);

	if (!process_shared_preload_libraries_in_progress)
		return;

	/* can't define PGC_POSTMASTER variable after startup */
	DefineCustomIntVariable("pgsentinel_ash.max_entries",
							"Maximum number of ash entries.",
							NULL,
							&ash_max_entries,
							1000,
							1000,
							INT_MAX,
							PGC_POSTMASTER,
							0,
							NULL,
							NULL,
							NULL);

	EmitWarningsOnPlaceholders("pgsentinel_ash");

	DefineCustomIntVariable("pgsentinel_pgssh.max_entries",
							"Maximum number of pgssh entries.",
							NULL,
							&pgssh_max_entries,
							10000,
							10000,
							INT_MAX,
							PGC_POSTMASTER,
							0,
							NULL,
							NULL,
							NULL);

	DefineCustomBoolVariable("pgsentinel_pgssh.enable",
	                        "Enable pg_stat_statements_history.",
							NULL,
							&pgssh_enable,
							false,
							PGC_POSTMASTER,
							0,
							NULL,
							NULL,
							NULL);

	EmitWarningsOnPlaceholders("pgsentinel_pgssh");

	DefineCustomStringVariable("pgsentinel.db_name",
							gettext_noop("Database on which the worker connect."),
							NULL,
							&pgsentinelDbName,
							"postgres",
							PGC_POSTMASTER,
							GUC_SUPERUSER_ONLY,
							NULL, NULL, NULL);
}

/*
 * Entry point for worker loading
 */
void
_PG_init(void)
{

	BackgroundWorker worker;

	if (IsBinaryUpgrade)
		return;

	/* Add parameters */
	pgsentinel_load_params();

	if (!process_shared_preload_libraries_in_progress)
		return;

#if PG_VERSION_NUM < 150000
	ash_shmem_request();
#endif

	/*
	 * Install hooks.
	 */
#if PG_VERSION_NUM >= 150000
	ash_prev_shmem_request_hook = shmem_request_hook;
	shmem_request_hook = ash_shmem_request;
#endif
	ash_prev_shmem_startup_hook = shmem_startup_hook;
	shmem_startup_hook = ash_shmem_startup;
	prev_post_parse_analyze_hook = post_parse_analyze_hook;
	post_parse_analyze_hook = getparsedinfo_post_parse_analyze;

	/* Worker parameter and registration */
	memset(&worker, 0, sizeof(worker));
	worker.bgw_flags = BGWORKER_SHMEM_ACCESS |
		BGWORKER_BACKEND_DATABASE_CONNECTION;
	worker.bgw_start_time = BgWorkerStart_ConsistentState;
#if PG_VERSION_NUM >= 100000
	sprintf(worker.bgw_library_name, "pgsentinel");
	sprintf(worker.bgw_function_name, "pgsentinel_main");
#else
	worker.bgw_main = pgsentinel_main;
#endif
	snprintf(worker.bgw_name, BGW_MAXLEN, "%s", worker_name);
	/* Wait ash_restart_wait_time seconds for restart before crash */
	worker.bgw_restart_time = ash_restart_wait_time;
	worker.bgw_main_arg = (Datum) 0;
#if PG_VERSION_NUM >= 90400
	/*
	 * Notify PID is present since 9.4. If this is not initialized
	 * a static background worker cannot start properly.
	 */
	worker.bgw_notify_pid = 0;
#endif
	RegisterBackgroundWorker(&worker);
}

static void
pg_active_session_history_internal(FunctionCallInfo fcinfo)
{
	ReturnSetInfo *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
	TupleDesc       tupdesc;
	Tuplestorestate *tupstore;
	MemoryContext per_query_ctx;
	MemoryContext oldcontext;
	int i;
	Oid         userid = GetUserId();
	bool        is_allowed_role = IS_ALLOWED_ROLE(userid);

	/* Entry array must exist already */
	if (!AshEntryArray)
		ereport(ERROR,
			(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				errmsg("pg_active_session_history must be loaded via shared_preload_libraries")));

	/* check to see if caller supports us returning a tuplestore */
	if (rsinfo == NULL || !IsA(rsinfo, ReturnSetInfo))
		ereport(ERROR,
			(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				errmsg("set-valued function called in context that cannot accept a set")));
	if (!(rsinfo->allowedModes & SFRM_Materialize))
		ereport(ERROR,
			(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				errmsg("materialize mode required, but it is not " \
					   "allowed in this context")));

	/* Switch context to construct returned data structures */
	per_query_ctx = rsinfo->econtext->ecxt_per_query_memory;
	oldcontext = MemoryContextSwitchTo(per_query_ctx);

	/* Build a tuple descriptor */
	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		elog(ERROR, "return type must be a row type");

	tupstore = tuplestore_begin_heap(true, false, work_mem);
	rsinfo->returnMode = SFRM_Materialize;
	rsinfo->setResult = tupstore;
	rsinfo->setDesc = tupdesc;

	MemoryContextSwitchTo(oldcontext);

	for (i = 0; i < ash_max_entries; i++)
	{
		Datum           values[PG_ACTIVE_SESSION_HISTORY_COLS];
		bool            nulls[PG_ACTIVE_SESSION_HISTORY_COLS];
		int                     j = 0;
		bool            show_text;

		memset(values, 0, sizeof(values));
		memset(nulls, 0, sizeof(nulls));

		// ash_time
		if (TimestampTzGetDatum(AshEntryArray[i].ash_time))
			values[j++] = TimestampTzGetDatum(AshEntryArray[i].ash_time);
		else
			break;

		// datid
		if (ObjectIdGetDatum(AshEntryArray[i].datid))
			values[j++] = ObjectIdGetDatum(AshEntryArray[i].datid);
		else
			nulls[j++] = true;

		// datname
		if (AshEntryArray[i].datname[0] != '\0')
			values[j++] = CStringGetTextDatum(AshEntryArray[i].datname);
		else
			nulls[j++] = true;

		// pid
		if (Int32GetDatum(AshEntryArray[i].pid))
			values[j++] = Int32GetDatum(AshEntryArray[i].pid);
		else
			nulls[j++] = true;

#if PG_VERSION_NUM >= 130000
		// leader_pid
		if (Int32GetDatum(AshEntryArray[i].leader_pid))
			values[j++] = Int32GetDatum(AshEntryArray[i].leader_pid);
		else
			nulls[j++] = true;
#else
			nulls[j++] = true;
#endif

		// usesysid
		if (ObjectIdGetDatum(AshEntryArray[i].usesysid))
			values[j++] = ObjectIdGetDatum(AshEntryArray[i].usesysid);
		else
			nulls[j++] = true;

		// usename
		if (AshEntryArray[i].usename[0] != '\0')
			values[j++] = CStringGetTextDatum(AshEntryArray[i].usename);
		else
			nulls[j++] = true;

		// application_name
		if (AshEntryArray[i].application_name[0] != '\0')
			values[j++] = CStringGetTextDatum(AshEntryArray[i].application_name);
		else
			nulls[j++] = true;

		// client_addr
		if (AshEntryArray[i].client_addr[0] != '\0')
			values[j++] = CStringGetTextDatum(AshEntryArray[i].client_addr);
		else
			nulls[j++] = true;

		// client_hostname
		if (AshEntryArray[i].client_hostname[0] != '\0')
			values[j++] = CStringGetTextDatum(AshEntryArray[i].client_hostname);
		else
			nulls[j++] = true;

		// client_port
		if (Int32GetDatum(AshEntryArray[i].client_port))
			values[j++] = Int32GetDatum(AshEntryArray[i].client_port);
		else
			nulls[j++] = true;

		// backend_start
		if (TimestampTzGetDatum(AshEntryArray[i].backend_start))
			values[j++] = TimestampTzGetDatum(AshEntryArray[i].backend_start);
		else
			nulls[j++] = true;

		// xact_start
		if (TimestampTzGetDatum(AshEntryArray[i].xact_start))
			values[j++] = TimestampTzGetDatum(AshEntryArray[i].xact_start);
		else
			nulls[j++] = true;

		// query_start
		if (TimestampTzGetDatum(AshEntryArray[i].query_start))
			values[j++] = TimestampTzGetDatum(AshEntryArray[i].query_start);
		else
			nulls[j++] = true;

		// state_change
		if (TimestampTzGetDatum(AshEntryArray[i].state_change))
			values[j++] = TimestampTzGetDatum(AshEntryArray[i].state_change);
		else
			nulls[j++] = true;

		// wait_event_type
		if (AshEntryArray[i].wait_event_type[0] != '\0')
			values[j++] = CStringGetTextDatum(AshEntryArray[i].wait_event_type);
		else
			nulls[j++] = true;

		// wait_event
		if (AshEntryArray[i].wait_event[0] != '\0')
			values[j++] = CStringGetTextDatum(AshEntryArray[i].wait_event);
		else
			nulls[j++] = true;

		// state
		if (AshEntryArray[i].state[0] != '\0')
			values[j++] = CStringGetTextDatum(AshEntryArray[i].state);
		else
			nulls[j++] = true;

		// backend_xid
		if (TransactionIdGetDatum(AshEntryArray[i].backend_xid))
			values[j++] = TransactionIdGetDatum(AshEntryArray[i].backend_xid);
		else
			nulls[j++] = true;

		// backend_xmin
		if (TransactionIdGetDatum(AshEntryArray[i].backend_xmin))
			values[j++] = TransactionIdGetDatum(AshEntryArray[i].backend_xmin);
		else
			nulls[j++] = true;

		show_text = is_allowed_role || AshEntryArray[i].usesysid == userid;

		// top_level_query - apply privilege check
		if (show_text)
		{
			if (AshEntryArray[i].top_level_query[0] != '\0')
				values[j++] = CStringGetTextDatum(AshEntryArray[i].top_level_query);
			else
				nulls[j++] = true;
		}
		else
		{
			values[j++] = CStringGetTextDatum("<insufficient privilege>");
		}

		// query - apply privilege check
		if (show_text)
		{
			if (AshEntryArray[i].query[0] != '\0')
				values[j++] = CStringGetTextDatum(AshEntryArray[i].query);
			else
				nulls[j++] = true;
		}
		else
		{
			values[j++] = CStringGetTextDatum("<insufficient privilege>");
		}

		// cmdtype
		if (AshEntryArray[i].cmdtype[0] != '\0')
                        values[j++] = CStringGetTextDatum(AshEntryArray[i].cmdtype);
		else
                        nulls[j++] = true;

		// query_id - apply privilege check
		if (show_text)
		{
			if (AshEntryArray[i].queryid)
				values[j++] = Int64GetDatum(AshEntryArray[i].queryid);
			else
				nulls[j++] = true;
		}
		else
		{
			nulls[j++] = true;
		}


		// backend_type
		if (AshEntryArray[i].backend_type[0] != '\0')
			values[j++] = CStringGetTextDatum(AshEntryArray[i].backend_type);
		else
			nulls[j++] = true;

		// blockers
		if (Int32GetDatum(AshEntryArray[i].blockers))
			values[j++] = Int32GetDatum(AshEntryArray[i].blockers);
		else
			nulls[j++] = true;

		// blockerspid
		if (Int32GetDatum(AshEntryArray[i].blockerpid))
			values[j++] = Int32GetDatum(AshEntryArray[i].blockerpid);
		else
			nulls[j++] = true;

		// blocker state
		if (AshEntryArray[i].blocker_state[0] != '\0')
			values[j++] = CStringGetTextDatum(AshEntryArray[i].blocker_state);
		else
			nulls[j++] = true;

		tuplestore_putvalues(tupstore, tupdesc, values, nulls);
	}
}


static void
pg_stat_statements_history_internal(FunctionCallInfo fcinfo)
{
	ReturnSetInfo *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
	TupleDesc       tupdesc;
	Tuplestorestate *tupstore;
	MemoryContext per_query_ctx;
	MemoryContext oldcontext;
	int i;
	Oid         userid = GetUserId();
	bool        is_allowed_role = IS_ALLOWED_ROLE(userid);

	if (!pgssh_enable)
		ereport(ERROR,
			(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				errmsg("pg_stat_statements_history not enabled, set pgsentinel_pgssh.enable")));
	/* Entry array must exist already */
	if (!PgsshEntryArray)
		ereport(ERROR,
			(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				errmsg("pg_stat_statements_history must be loaded via shared_preload_libraries")));

	/* check to see if caller supports us returning a tuplestore */
	if (rsinfo == NULL || !IsA(rsinfo, ReturnSetInfo))
		ereport(ERROR,
			(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				errmsg("set-valued function called in context that cannot accept a set")));
	if (!(rsinfo->allowedModes & SFRM_Materialize))
		ereport(ERROR,
			(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				errmsg("materialize mode required, but it is not " \
					   "allowed in this context")));

	/* Switch context to construct returned data structures */
	per_query_ctx = rsinfo->econtext->ecxt_per_query_memory;
	oldcontext = MemoryContextSwitchTo(per_query_ctx);

	/* Build a tuple descriptor */
	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		elog(ERROR, "return type must be a row type");

	tupstore = tuplestore_begin_heap(true, false, work_mem);
	rsinfo->returnMode = SFRM_Materialize;
	rsinfo->setResult = tupstore;
	rsinfo->setDesc = tupdesc;

	MemoryContextSwitchTo(oldcontext);

	for (i = 0; i < pgssh_max_entries; i++)
	{
		Datum           values[PG_STAT_STATEMENTS_HISTORY_COLS];
		bool            nulls[PG_STAT_STATEMENTS_HISTORY_COLS];
		int             j = 0;
		bool            show_text;
#if PG_VERSION_NUM >= 130000
		char        buf[256];
		Datum       wal_bytes;
#endif

		memset(values, 0, sizeof(values));
		memset(nulls, 0, sizeof(nulls));

		// ash_time
		if (TimestampTzGetDatum(PgsshEntryArray[i].ash_time))
			values[j++] = TimestampTzGetDatum(PgsshEntryArray[i].ash_time);
		else
			break;

		// userid
		if (ObjectIdGetDatum(PgsshEntryArray[i].userid))
			values[j++] = ObjectIdGetDatum(PgsshEntryArray[i].userid);
		else
			nulls[j++] = true;

		// dbid
		if (ObjectIdGetDatum(PgsshEntryArray[i].dbid))
			values[j++] = ObjectIdGetDatum(PgsshEntryArray[i].dbid);
		else
			nulls[j++] = true;

		show_text = is_allowed_role || PgsshEntryArray[i].userid == userid;

		// query_id - apply privilege check
		if (show_text)
		{
			if (Int64GetDatum(PgsshEntryArray[i].queryid))
				values[j++] = Int64GetDatum(PgsshEntryArray[i].queryid);
			else
				nulls[j++] = true;
		}
		else
		{
			nulls[j++] = true;
		}

		// calls
		if (Int64GetDatum(PgsshEntryArray[i].calls))
			values[j++] = Int64GetDatum(PgsshEntryArray[i].calls);
		else
			values[j++] = 0;

		// total_time
		if (Float8GetDatum(PgsshEntryArray[i].total_time))
			values[j++] = Float8GetDatum(PgsshEntryArray[i].total_time);
		else
			values[j++] = 0;

		// rows
		if (Int64GetDatum(PgsshEntryArray[i].rows))
			values[j++] = Int64GetDatum(PgsshEntryArray[i].rows);
		else
			values[j++] = 0;

		// shared_blks_hit
		if (Int64GetDatum(PgsshEntryArray[i].shared_blks_hit))
			values[j++] = Int64GetDatum(PgsshEntryArray[i].shared_blks_hit);
		else
			values[j++] = 0;

		// shared_blks_read
		if (Int64GetDatum(PgsshEntryArray[i].shared_blks_read))
			values[j++] = Int64GetDatum(PgsshEntryArray[i].shared_blks_read);
		else
			values[j++] = 0;

		// shared_blks_dirtied
		if (Int64GetDatum(PgsshEntryArray[i].shared_blks_dirtied))
			values[j++] = Int64GetDatum(PgsshEntryArray[i].shared_blks_dirtied);
		else
			values[j++] = 0;

		// shared_blks_written
		if (Int64GetDatum(PgsshEntryArray[i].shared_blks_written))
			values[j++] = Int64GetDatum(PgsshEntryArray[i].shared_blks_written);
		else
			values[j++] = 0;

		// local_blks_hit
		if (Int64GetDatum(PgsshEntryArray[i].local_blks_hit))
			values[j++] = Int64GetDatum(PgsshEntryArray[i].local_blks_hit);
		else
			values[j++] = 0;

		// local_blks_read
		if (Int64GetDatum(PgsshEntryArray[i].local_blks_read))
			values[j++] = Int64GetDatum(PgsshEntryArray[i].local_blks_read);
		else
			values[j++] = 0;

		// local_blks_dirtied
		if (Int64GetDatum(PgsshEntryArray[i].local_blks_dirtied))
			values[j++] = Int64GetDatum(PgsshEntryArray[i].local_blks_dirtied);
		else
			values[j++] = 0;

		// local_blks_written
		if (Int64GetDatum(PgsshEntryArray[i].local_blks_written))
			values[j++] = Int64GetDatum(PgsshEntryArray[i].local_blks_written);
		else
			values[j++] = 0;

		// temp_blks_read
		if (Int64GetDatum(PgsshEntryArray[i].temp_blks_read))
			values[j++] = Int64GetDatum(PgsshEntryArray[i].temp_blks_read);
		else
			values[j++] = 0;

		// temp_blks_written
		if (Int64GetDatum(PgsshEntryArray[i].temp_blks_written))
			values[j++] = Int64GetDatum(PgsshEntryArray[i].temp_blks_written);
		else
			values[j++] = 0;

		// blk_read_time
		if (Float8GetDatum(PgsshEntryArray[i].blk_read_time))
			values[j++] = Float8GetDatum(PgsshEntryArray[i].blk_read_time);
		else
			values[j++] = 0;

		// blk_write_time
		if (Float8GetDatum(PgsshEntryArray[i].blk_write_time))
			values[j++] = Float8GetDatum(PgsshEntryArray[i].blk_write_time);
		else
			values[j++] = 0;
#if PG_VERSION_NUM >= 130000
		// plans
		if (Int64GetDatum(PgsshEntryArray[i].plans))
			values[j++] = Int64GetDatum(PgsshEntryArray[i].plans);
		else
			values[j++] = 0;

		// total_plan_time
		if (Float8GetDatum(PgsshEntryArray[i].total_plan_time))
			values[j++] = Float8GetDatum(PgsshEntryArray[i].total_plan_time);
		else
			values[j++] = 0;

		// wal_records
		if (Int64GetDatum(PgsshEntryArray[i].wal_records))
			values[j++] = Int64GetDatum(PgsshEntryArray[i].wal_records);
		else
			values[j++] = 0;

		// wal_fpi
		if (Int64GetDatum(PgsshEntryArray[i].wal_fpi))
			values[j++] = Int64GetDatum(PgsshEntryArray[i].wal_fpi);
		else
			values[j++] = 0;

		// wal_bytes
		snprintf(buf, sizeof buf, UINT64_FORMAT, PgsshEntryArray[i].wal_bytes);
		/* Convert to numeric. */
		wal_bytes = DirectFunctionCall3(numeric_in,
										CStringGetDatum(buf),
										ObjectIdGetDatum(0),
										Int32GetDatum(-1));

		values[j++] = wal_bytes;
#else
		nulls[j++] = true;
		nulls[j++] = true;
		nulls[j++] = true;
		nulls[j++] = true;
		nulls[j++] = true;
#endif
		tuplestore_putvalues(tupstore, tupdesc, values, nulls);
        }
}

Datum
pg_active_session_history(PG_FUNCTION_ARGS)
{
	pg_active_session_history_internal(fcinfo);
	return (Datum) 0;
}

Datum
pg_stat_statements_history(PG_FUNCTION_ARGS)
{
	pg_stat_statements_history_internal(fcinfo);
	return (Datum) 0;
}

void
_PG_fini(void)
{
	/* Uninstall hooks. */
	shmem_startup_hook = ash_prev_shmem_startup_hook;
	post_parse_analyze_hook = prev_post_parse_analyze_hook;
}

static bool
PgSentinelHasBeenLoaded(void)
{
	bool extensionLoaded = false;
	bool extensionPresent = false;
	bool extensionScriptExecuted = true;

	Oid extensionOid = get_extension_oid(EXTENSION_NAME, true);
	if (extensionOid != InvalidOid)
		extensionPresent = true;

	if (extensionPresent)
	{
		/* check if extension objects are still being created */
		if (creating_extension && CurrentExtensionObject == extensionOid)
			extensionScriptExecuted = false;
		else if (IsBinaryUpgrade)
			extensionScriptExecuted = false;
	}

	extensionLoaded = extensionPresent && extensionScriptExecuted;

	return extensionLoaded;
}

/*
 * shmem_request hook: request additional shared resources.  We'll allocate or
 * attach to the shared resources in ash_shmem_startup().
 */
static void
ash_shmem_request(void)
{
#if PG_VERSION_NUM >= 150000
    if (ash_prev_shmem_request_hook)
		ash_prev_shmem_request_hook();
#endif
	RequestAddinShmemSpace(ash_entry_memsize());
	RequestNamedLWLockTranche("Ash Entry Array", 1);

	RequestAddinShmemSpace(proc_entry_memsize());
	RequestNamedLWLockTranche("Get_parsedinfo Proc Entry Array", 1);

	RequestAddinShmemSpace(int_entry_memsize());
	RequestNamedLWLockTranche("Int Entry Array", 1);

	if (pgssh_enable)
	{
		RequestAddinShmemSpace(pgssh_entry_memsize());
		RequestNamedLWLockTranche("Pgssh Entry Array", 1);
	}
}
