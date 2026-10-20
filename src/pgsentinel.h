#ifndef __PG_SENTINEL_H__
#define __PG_SENTINEL_H__

#include <postgres.h>
#include "parser/analyze.h"

/* Check PostgreSQL version */
#if PG_VERSION_NUM < 90600
        #error "You are trying to build pg_sentinel with PostgreSQL version < 9.6"
#endif

/* Saved hook values in case of unload */
extern post_parse_analyze_hook_type prev_post_parse_analyze_hook;

/*
 * post_parse_analyze_hook takes a const JumbleState from PostgreSQL 19 on.
 * Spell the qualifier once so the hook's declaration and definition cannot
 * drift apart.
 */
#if PG_VERSION_NUM >= 190000
#define PGS_JUMBLESTATE const JumbleState
#else
#define PGS_JUMBLESTATE JumbleState
#endif

/* Our hooks */
#if PG_VERSION_NUM < 140000
extern void getparsedinfo_post_parse_analyze(ParseState *pstate, Query *query);
#else
extern void getparsedinfo_post_parse_analyze(ParseState *pstate, Query *query, PGS_JUMBLESTATE *jstate);
#endif
/* Estimate amount of shared memory needed */
extern Size proc_entry_memsize(void);
extern int get_max_procs_count(void);

typedef struct procEntry
{
        uint64 queryid;
        char *query;
        char *cmdtype;
} procEntry;

extern procEntry *ProcEntryArray;
extern int proc_entry_count;

#endif
