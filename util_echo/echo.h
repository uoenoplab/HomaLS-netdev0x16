#ifndef _ECHO_H
#define _ECHO_H

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h> 
#include <linux/tls.h>

#include "../homa.h"
#include "../homals_uapi.h"

enum {
    ECHO_HOMA,
    ECHO_HOMALS,
    ECHO_HOMALSALT,
    ECHO_PROTO_NUM
};

static const char* protocol_names[ECHO_PROTO_NUM] = {
    "homa", "homals", "homalsalt"
};

extern int compare_float(const void * a, const void * b);

extern double calculate_time_delta_us(struct timespec a, struct timespec b);
extern double calculate_time_delta_s(struct timespec a, struct timespec b);

extern int get_protocol(char const *protocol_name);
extern void print_protocol_names();

extern void set_crypto_info(struct tls12_crypto_info_aes_gcm_128 *crypto_info_send, struct tls12_crypto_info_aes_gcm_128 *crypto_info_read, int server);
extern void set_crypto_info_alter(struct tls12_crypto_info_aes_gcm_128 *crypto_info_send, struct tls12_crypto_info_aes_gcm_128 *crypto_info_read, int server); // for 2 echo client with different keys
extern void set_crypto_info_tls12(struct tls12_crypto_info_aes_gcm_128 *crypto_info_send, struct tls12_crypto_info_aes_gcm_128 *crypto_info_read, int server);

#endif /* _ECHO_H */
