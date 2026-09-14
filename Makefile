CC ?= cc
CC32 ?= $(CC) -m32
AR ?= ar
CCLD ?= $(CC)
CCLD32 ?= $(CC32)
COMMON_CFLAGS := -Wall -Wpedantic -Wextra -fPIC
ASAN_FLAGS := -fsanitize=address,undefined
CFLAGS ?=
SO_LDFLAGS := -shared
DEPFLAGS?=-MMD -MP
LDFLAGS?=-pie -Wl,-hash-style=both
ARFLAGS=rcs
LIBS?=
STRIP?=strip
DEBUGSTRIP?=strip -d
STRIPFLAGS?=-g -s

ECHO=echo
PRINTF=printf
RM=rm -f
TOUCH=touch -c
EXEC=exec
MKDIR=mkdir -p
RMRF=rm -rf
CP := cp

EXEPREFIX =
EXESUFFIX =
OBJDIR = obj
BINDIR = bin

TEST_LIB_SRC := tests/test-lib.c
TEST_EXE_SRC := tests/test-exe.c
SUS_LIB_SRC := tests/sus.c
TEST_SRCS := $(TEST_LIB_SRC) $(TEST_EXE_SRC) $(SUS_LIB_SRC)
TEST_EXE := $(BINDIR)/test
TEST_EXE32 := $(BINDIR)/test32
TEST_LIB := $(BINDIR)/test-lib.so
TEST_LIB_COPY := $(BINDIR)/test-lib.orig.so
TEST_LIB32 := $(BINDIR)/test-lib32.so
TEST_LIB32_COPY := $(BINDIR)/test-lib32.orig.so
SUS_LIB := $(BINDIR)/libsus.so
SUS_LIB32 := $(BINDIR)/libsus32.so
SUS_LIB_LDFLAGS := #-nostdlib

TEST_ARTIFACTS := $(TEST_EXE) $(TEST_EXE32) $(TEST_LIB) $(TEST_LIB32) $(TEST_LIB_COPY) $(TEST_LIB32_COPY)

SRCS=$(filter-out $(TEST_SRCS),$(shell find $(wildcard *) -type f -name "*.c" ))
OBJS=$(patsubst %,$(OBJDIR)/%.o,$(shell echo $(SRCS) | xargs basename -as .c))
DEPS=$(patsubst %.o,%.d,$(OBJS))
STRIP_OBJS=

EXE=$(BINDIR)/$(EXEPREFIX)elf-add-import$(EXESUFFIX)
EXEARGS=

RUN_CMDLINE := '$(EXE) $(TEST_LIB_COPY) $(TEST_LIB)'
RUN32_CMDLINE := '$(EXE) $(TEST_LIB32_COPY) $(TEST_LIB32)'

RED=[31;1m
GREEN=[32;1m
COL_RESET=[0m
#RED=
#GREEN=
#COL_RESET=

.PHONY: all release strip clean mostlyclean update run br tests build-tests run-tests
.NOTPARALLEL: all release br $(TEST_LIB) $(TEST_LIB32) $(TEST_EXE) $(TEST_EXE32)

all: CFLAGS += -ggdb -O0 -Wall $(ASAN_FLAGS)
all: LDFLAGS += $(ASAN_FLAGS)
all: $(OBJDIR) $(BINDIR) $(EXE)

release: CFLAGS += -O3 -Wall -Werror -DBUILD_TYPE_RELEASE
release: clean $(OBJDIR) $(BINDIR) $(EXE) tests mostlyclean strip

br: all run

$(EXE): $(OBJS)
#@$(DEBUGSTRIP) $(STRIP_OBJS) 2>/dev/null
	@$(PRINTF) "CCLD 	%-30s %-30s\n" "$(EXE)" "<= $(OBJS) $(LIBS)"
	@$(CCLD) $(LDFLAGS) -o $(EXE) $(OBJS) $(LIBS)

$(TEST_LIB): CFLAGS += $(ASAN_FLAGS)
$(TEST_LIB): LDFLAGS += $(ASAN_FLAGS)
$(TEST_LIB): $(BINDIR) $(TEST_LIB_SRC) Makefile
	@$(PRINTF) "CCLD	%-30s %-30s\n" "$(TEST_LIB)" "<= $(TEST_LIB_SRC)"
	@$(CCLD) $(COMMON_CFLAGS) $(CFLAGS) $(LDFLAGS) $(SO_LDFLAGS) -o $(TEST_LIB) $(TEST_LIB_SRC)

$(TEST_LIB32): CFLAGS += $(ASAN_FLAGS)
$(TEST_LIB32): LDFLAGS += $(ASAN_FLAGS)
$(TEST_LIB32): $(BINDIR) $(TEST_LIB_SRC) Makefile
	@$(PRINTF) "CCLD32	%-30s %-30s\n" "$(TEST_LIB32)" "<= $(TEST_LIB_SRC)"
	@$(CCLD32) $(COMMON_CFLAGS) $(CFLAGS) $(LDFLAGS) $(SO_LDFLAGS) -o $(TEST_LIB32) $(TEST_LIB_SRC)

$(TEST_EXE): CFLAGS += $(ASAN_FLAGS)
$(TEST_EXE): LDFLAGS += $(ASAN_FLAGS)
$(TEST_EXE): $(BINDIR) $(TEST_LIB) $(TEST_LIB_COPY) $(TEST_EXE_SRC) $(SUS_LIB) Makefile
	@$(PRINTF) "CCLD	%-30s %-30s\n" "$(TEST_EXE)" "<= $(TEST_EXE_SRC) $(TEST_LIB)"
	@$(CCLD) $(COMMON_CFLAGS) $(CFLAGS) $(LDFLAGS) $(TEST_LIB) -o $(TEST_EXE) $(TEST_EXE_SRC)

$(TEST_EXE32): CFLAGS += $(ASAN_FLAGS)
$(TEST_EXE32): LDFLAGS += $(ASAN_FLAGS)
$(TEST_EXE32): $(BINDIR) $(TEST_LIB32) $(TEST_LIB32_COPY) $(TEST_EXE_SRC) $(SUS_LIB32) Makefile
	@$(PRINTF) "CCLD32	%-30s %-30s\n" "$(TEST_EXE32)" "<= $(TEST_EXE_SRC) $(TEST_LIB32)"
	@$(CCLD32) $(COMMON_CFLAGS) $(CFLAGS) $(LDFLAGS) $(TEST_LIB32) -o $(TEST_EXE32) $(TEST_EXE_SRC)

$(SUS_LIB): CFLAGS += $(ASAN_FLAGS)
$(SUS_LIB): LDFLAGS += $(ASAN_FLAGS) $(SUS_LIB_LDFLAGS)
$(SUS_LIB): $(BINDIR) $(SUS_LIB_SRC) Makefile
	@$(PRINTF) "CCLD	%-30s %-30s\n" "$(SUS_LIB)" "<= $(SUS_LIB_SRC)"
	@$(CCLD) $(COMMON_CFLAGS) $(CFLAGS) $(LDFLAGS) $(SO_LDFLAGS) -o $(SUS_LIB) $(SUS_LIB_SRC)

$(SUS_LIB32): CFLAGS += $(ASAN_FLAGS)
$(SUS_LIB32): LDFLAGS += $(ASAN_FLAGS) $(SUS_LIB_LDFLAGS)
$(SUS_LIB32): $(BINDIR) $(SUS_LIB32_SRC) Makefile
	@$(PRINTF) "CCLD	%-30s %-30s\n" "$(SUS_LIB32)" "<= $(SUS_LIB_SRC)"
	@$(CCLD32) $(COMMON_CFLAGS) $(CFLAGS) $(LDFLAGS) $(SO_LDFLAGS) -o $(SUS_LIB32) $(SUS_LIB_SRC)

$(TEST_LIB_COPY): $(TEST_LIB)
	@$(PRINTF) "CP	%-30s %-30s\n" "$(TEST_LIB)" "=> $(TEST_LIB_COPY)"
	@$(CP) $(TEST_LIB) $(TEST_LIB_COPY)
	@$(TOUCH) -r $(TEST_LIB) $(TEST_LIB_COPY)

$(TEST_LIB32_COPY): $(TEST_LIB32)
	@$(PRINTF) "CP	%-30s %-30s\n" "$(TEST_LIB32)" "=> $(TEST_LIB32_COPY)"
	@$(CP) $(TEST_LIB32) $(TEST_LIB32_COPY)
	@$(TOUCH) -r $(TEST_LIB32) $(TEST_LIB32_COPY)

$(OBJDIR):
	@$(ECHO) "MKDIR	$(OBJDIR)"
	@$(MKDIR) $(OBJDIR)

$(BINDIR):
	@$(ECHO) "MKDIR	$(BINDIR)"
	@$(MKDIR) $(BINDIR)

$(TEST_EXE_DIR):
	@$(ECHO) "MKDIR	$(TEST_EXE_DIR)"
	@$(MKDIR) $(TEST_EXE_DIR)

$(OBJDIR)/%.o: ./%.c Makefile
	@$(PRINTF) "CC 	%-30s %-30s\n" "$@" "<= $<"
	@$(CC) $(DEPFLAGS) $(COMMON_CFLAGS) $(CFLAGS) -c -o $@ $<

$(OBJDIR)/%.o: */%.c Makefile
	@$(PRINTF) "CC 	%-30s %-30s\n" "$@" "<= $<"
	@$(CC) $(DEPFLAGS) $(COMMON_CFLAGS) $(CFLAGS) -c -o $@ $<

tests: CFLAGS += -ggdb -O0 -Wall
tests: $(OBJDIR) $(BINDIR) $(EXE) build-tests
	@n_passed=0; \
	for i in $(TEST_EXE) $(TEST_EXE32) $(RUN_CMDLINE) $(RUN32_CMDLINE) $(TEST_EXE) $(TEST_EXE32); do \
		$(PRINTF) "EXEC	%s\n" "$$i"; \
		if $$i; then \
			$(PRINTF) "$(GREEN)OK$(COL_RESET)\n"; \
			n_passed="$$((n_passed + 1))"; \
		else \
			$(PRINTF) "$(RED)FAIL$(COL_RESET)\n"; \
		fi; \
	done; \
	n_total=6; \
	if test "$$n_passed" -lt "$$n_total"; then \
		$(PRINTF) "$(RED)"; \
	else \
		$(PRINTF) "$(GREEN)"; \
	fi; \
	$(PRINTF) "%s/%s$(COL_RESET) tests passed.\n" "$$n_passed" "$$n_total";

build-tests: compile-tests

compile-tests: $(TEST_EXE) $(TEST_EXE32)

run-tests: tests

strip:
	@$(ECHO) "STRIP	$(EXE)"
	@$(STRIP) $(STRIPFLAGS) $(EXE)

mostlyclean:
	@$(ECHO) "RM	$(OBJS) $(DEPS)"
	@$(RM) $(OBJS) $(DEPS)

clean:
	@$(ECHO) "RM	$(OBJS) $(DEPS) $(EXE) $(TEST_ARTIFACTS) $(BINDIR) $(OBJDIR)"
	@$(RM) $(OBJS) $(DEPS) $(EXE) $(TEST_ARTIFACTS)
	@$(RMRF) $(OBJDIR) $(BINDIR)

update:
	@$(ECHO) "TOUCH	$(SRCS)"
	@$(TOUCH) $(SRCS)

run:
	@$(ECHO) "EXEC	$(EXE) $(EXEARGS)"
	@$(EXEC) $(EXE) $(EXEARGS)

-include $(DEPS)
