WOLFPSA_PATH ?= ..
WOLFSSL_PATH ?= $(WOLFPSA_PATH)/../wolfssl

CC ?= cc

CFLAGS ?= -O2
WARNFLAGS ?= -Wall -Wextra -Werror
CFLAGS += $(WARNFLAGS)

CPPFLAGS += -DHAVE_CONFIG_H -DWOLFSSL_HAVE_PSA -DHAVE_PK_CALLBACKS
CPPFLAGS += -I$(WOLFSSL_PATH)/build -I$(WOLFSSL_PATH) -I$(WOLFSSL_PATH)/wolfssl
CPPFLAGS += -I$(WOLFPSA_PATH) -I$(WOLFPSA_PATH)/wolfpsa
CPPFLAGS += -I$(WOLFPSA_PATH)/test/psa_server

LDFLAGS += -L$(WOLFSSL_PATH)/build -L$(WOLFPSA_PATH)
LDLIBS += -lwolfssl -lwolfpsa -lpthread -lm

RPATH_WOLFPSA = -Wl,-rpath,'$$ORIGIN/..'
RPATH_WOLFSSL = -Wl,-rpath,$(WOLFSSL_PATH)/build

BINARIES = psa_api_test psa_tls_server psa_tls_client wolfcrypt-psa-benchmark

.PHONY: all clean

all: $(BINARIES)

psa_api_test: psa_server/psa_api_test.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LDLIBS) $(RPATH_WOLFPSA) $(RPATH_WOLFSSL)

psa_tls_server: psa_server/psa_tls_server.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LDLIBS) $(RPATH_WOLFPSA) $(RPATH_WOLFSSL)

psa_tls_client:
	make -C psa_server/tls_client
	cp psa_server/tls_client/psa_tls_client ./psa_tls_client

wolfcrypt-psa-benchmark:
	make -C wolfcrypt-benchmark
	cp wolfcrypt-benchmark/wolfcrypt-psa-benchmark ./wolfcrypt-psa-benchmark

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

clean:
	make -C psa_server/tls_client clean
	make -C wolfcrypt-benchmark clean
	rm -f psa_server/*.o
	rm -f $(BINARIES) *.o *.log
