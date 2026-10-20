# Server settings for the tests; installcheck-all swaps in the pgssh-disabled
# ones for that suite.
PGSENTINEL_CONF ?= pgsentinel.conf

ifdef DEB_BUILD_GNU_TYPE
    # Against a running server configured with $(PGSENTINEL_CONF). Its
    # pgsentinel worker stays connected to the regression database, so the
    # isolation run reuses that database rather than dropping it.
    REGRESS_OPTS =--temp-config=./$(PGSENTINEL_CONF)
    ISOLATION_OPTS = --use-existing
else
    REGRESS_OPTS =--temp-config=./$(PGSENTINEL_CONF) --temp-instance=./tmp_check
    ISOLATION_OPTS = --temp-config=./$(PGSENTINEL_CONF) --temp-instance=./tmp_check_iso
endif

REGRESS = pgsentinel-test pgsentinel-upgrade-test
ISOLATION = pgsentinel-blockers

MODULE_big = pgsentinel
OBJS = $(patsubst %.c,%.o,$(wildcard ./*.c))

ifeq ($(CC),gcc)
    PG_CPPFLAGS = -std=gnu11 -Wall -Wextra -Werror -Wno-unused-parameter -Wno-uninitialized -Wno-implicit-fallthrough -Iinclude
else
    PG_CPPFLAGS = -std=gnu11 -Wall -Wextra -Werror -Wno-unused-parameter -Wno-implicit-fallthrough -Iinclude
endif

EXTRA_CLEAN += $(addprefix ./,*.gcno *.gcda)

EXTENSION = pgsentinel
DATA = $(wildcard $(EXTENSION)*--*.sql)
PGFILEDESC = "pgsentinel - active session history"

LDFLAGS_SL += $(filter -lm, $(LIBS))

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

# The worker samples only while the extension exists in pgsentinel.db_name,
# which the test configurations set to the regression database.
ISOLATION_TESTDB = contrib_regression

# Every suite, each on throwaway instances: no running server is touched.
.PHONY: installcheck-all
installcheck-all:
	$(MAKE) installcheck
	$(MAKE) installcheck REGRESS=pgsentinel-disabled-test ISOLATION= \
		PGSENTINEL_CONF=pgsentinel-disabled.conf
