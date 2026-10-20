CC     ?= gcc
CFLAGS ?= -O3 -march=native -std=c11 -D_GNU_SOURCE -Wall -Wextra -Wno-unused-function
LDLIBS  = -lm -lpthread

BIN = bin

all: $(BIN)/test_ref $(BIN)/dfa

$(BIN):
	mkdir -p $(BIN)

$(BIN)/test_ref: ref/test_ref.c ref/dipper.c ref/ks_inv.h variants/cipher.h | $(BIN)
	$(CC) $(CFLAGS) -o $@ ref/test_ref.c ref/dipper.c $(LDLIBS)

$(BIN)/dfa: sim/dfa_run.c attack/dfa.h attack/deep.h attack/chain.h sim/fault.h ref/dipper.c ref/ks_inv.h variants/cipher.h | $(BIN)
	$(CC) $(CFLAGS) -o $@ sim/dfa_run.c ref/dipper.c $(LDLIBS)

test: $(BIN)/test_ref
	$(BIN)/test_ref 10000 0x5EED0001

clean:
	rm -rf $(BIN)

.PHONY: all test clean
