.PHONY: all debug clean

outputs = echo_client echo_server
objects = echo.o homa_api.o

CFLAGS_ECHO = 
# CFLAGS_ECHO = -ltomcrypt -ltommath -DLTM_DESC -DNO_TLS_LEGACY_SUPPORT -DTLS_CURVE25519 -DWITH_KTLS -DTLS_RX -DDEBUG

CC = gcc -O3
# CC = gcc -g

all: $(outputs)

debug: CC = gcc -g
debug: CFLAGS_ECHO += -DDEBUG
debug: all;

$(outputs): %: %.c $(objects)
	$(CC) $@.c $(objects) $(CFLAGS_ECHO)  -o $@ 

echo.o : echo.c echo.h
	$(CC) echo.c $(CFLAGS_ECHO) -c -o $@

homa_api.o : ../homa_api.c ../homa.h
	$(CC) ../homa_api.c -c -o $@

clean: 
	-rm $(objects) $(outputs)
