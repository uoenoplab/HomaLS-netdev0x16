#include "echo.h"

const int recv_buflen = HOMA_MAX_MESSAGE_LENGTH;
unsigned char recv_buf[HOMA_MAX_MESSAGE_LENGTH];

int build_random_request(unsigned char *reqmsg, size_t reqlen) {
    for (size_t i = 0; i < reqlen; i++)
    {
        reqmsg[i] = i % 256;
    }
    // FILE *fp = fopen("/dev/urandom", "r");
    // if (fp) {
    //     int reqlen_random = fread(reqmsg, 1, reqlen, fp);
    //     fclose(fp);
    //     if (reqlen_random == reqlen) {
    //         return 1;
    //     } else {
    //         return -1;
    //     }
    // }
}

int homa_send_recv(int sockfd, const unsigned char *request, int reqlen, struct sockaddr_in *addr_ptr, float *rtt) {
    size_t addr_len = sizeof(*addr_ptr);
    uint64_t rpcid = 0;
    struct timespec start_time, end_time;
    size_t reslen;
    int ret;
    float rtt_tmp;
    if (rtt == NULL) rtt = &rtt_tmp;

#ifdef DEBUG
    fprintf(stdout, "Client send (len: %d): \n", reqlen);
    for (size_t i = 0; i < reqlen; i++) {
        fprintf(stdout, "%02hhX ", request[i]);
    }
    fprintf(stdout, "\n");
#endif
    
    clock_gettime(CLOCK_MONOTONIC_RAW, &start_time);

    ret = homa_send(sockfd, request, reqlen, (struct sockaddr*)addr_ptr, addr_len, &rpcid);
    // char *buf[] = {
    //         "The term buccaneer comes from the word boucan.\n",
    //         "A boucan is a wooden frame used for cooking meat.\n",
    //         "Buccaneer is the West Indies name for a pirate.\n" };
    // size_t iovcnt = 3;
    // struct iovec iov[iovcnt];
    // for (int i = 0; i < 3; i++) {
    //         iov[i].iov_base = buf[i];
    //         iov[i].iov_len = strlen(buf[i]) + 1;
    // }
    // ret = homa_sendv(sockfd, iov, iovcnt, (struct sockaddr*)addr_ptr, addr_len, &rpcid);

    if (ret == -1) {
        printf("Couldn't send Homa msg: %s\n", strerror(errno));
        return -1;
    }

    ret = homa_recv(sockfd, recv_buf, recv_buflen, HOMA_RECV_RESPONSE, (struct sockaddr*)addr_ptr, &addr_len, &rpcid, &reslen);
    if (ret == -1) {
        printf("Couldn't receive Homa msg: %s\n", strerror(errno));
        return -1;
    }

    clock_gettime(CLOCK_MONOTONIC_RAW, &end_time);
    *rtt = calculate_time_delta_us(end_time, start_time);

#ifdef DEBUG
    printf("Client recv (reslen %ld, rpcid %ld, rtt (us) %.2lf): \n", reslen, rpcid, *rtt);
    for (size_t i = 0; i < reslen; i++) {
        fprintf(stdout, "%02hhX ", recv_buf[i]);
    }
    fprintf(stdout, "\n");
#endif

    return reslen;
}

int main(int argc, char const *argv[])
{
    int port, reqlen, reqnum, protocol;
    int sockfd, ret;
    struct sockaddr_in server_addr;
    size_t server_addrlen = sizeof(server_addr);
    struct TLSContext *tls_context;
    
    if (argc < 6) {
        fprintf(stdout, "usage %s hostname port reqsize reqnum protocol\n", argv[0]);
        exit(0);
    }
    
    struct hostent *server_hostent = gethostbyname(argv[1]);
    if (server_hostent == NULL) {
        printf("Get hostname ip failed: %s\n", strerror(errno));
        exit(0);
    }

    port = atoi(argv[2]);
    reqlen = atoi(argv[3]);
    reqnum = atoi(argv[4]);

    protocol = get_protocol(argv[5]);
    if (protocol == ECHO_PROTO_NUM) {
        print_protocol_names();
        return 1;
    }

    memset((char *)&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    memcpy((char *)&server_addr.sin_addr.s_addr, (char *)server_hostent->h_addr, server_hostent->h_length);
    server_addr.sin_port = htons(port);

    float rtts[reqnum];
    char request[reqlen + 5 + 1 + 16];

    if (build_random_request(request, reqlen) == -1) {
        printf("Build random request failed\n");
        return 1;
    }
    
    if (protocol == ECHO_HOMA || protocol == ECHO_HOMALS || protocol == ECHO_HOMALSALT) {
        sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_HOMA);
        if (sockfd < 0) {
            printf("Couldn't open Homa socket: %s\n", strerror(errno));
            return 1;
        }

        if (protocol == ECHO_HOMALS || protocol == ECHO_HOMALSALT) {
            struct homals_crypto_info homals_info_send, homals_info_read;

            if (protocol == ECHO_HOMALS)
                set_crypto_info(
                    &(homals_info_send.crypto_info_aes_gcm_128), 
                    &(homals_info_read.crypto_info_aes_gcm_128), 0);

            if (protocol == ECHO_HOMALSALT)
                set_crypto_info_alter(
                    &(homals_info_send.crypto_info_aes_gcm_128), 
                    &(homals_info_read.crypto_info_aes_gcm_128), 0);

            memcpy((char *)&homals_info_send.addr, (char *)server_hostent->h_addr, sizeof(homals_info_send.addr));
            memcpy((char *)&homals_info_read.addr, (char *)server_hostent->h_addr, sizeof(homals_info_read.addr));

            homals_info_send.port = htons(port);
            homals_info_read.port = htons(port);

            ret = setsockopt(sockfd, SOL_TLS, TLS_TX, &homals_info_send, sizeof(homals_info_send));
            if (ret < 0) {
                printf("Couldn't set TLS_TX option on homals: %d %s\n", ret, strerror(errno));
                return 1;
            }
            
            ret = setsockopt(sockfd, SOL_TLS, TLS_RX, &homals_info_read, sizeof(homals_info_read));
            if (ret < 0) {
                printf("Couldn't set TLS_RX option values on homals: %d %s\n", ret, strerror(errno));
                return 1;
            }
        }
    }

    struct timespec loop_start_time, loop_end_time;
    clock_gettime(CLOCK_MONOTONIC_RAW, &loop_start_time);
    for (size_t i = 0; i < reqnum; i++) {
        switch (protocol)
        {
        case ECHO_HOMA:
        case ECHO_HOMALS:
        case ECHO_HOMALSALT:
            ret = homa_send_recv(sockfd, request, reqlen, &server_addr, &rtts[i]);
            break;
        default:
            printf("unsupported protocol");
            exit(1);
        }
        if (ret == -1) return 1;
    }
    clock_gettime(CLOCK_MONOTONIC_RAW, &loop_end_time);

    printf("Total time (s) %.6f\n", calculate_time_delta_s(loop_end_time, loop_start_time));

    double avg_rtt = 0.0;
    for (size_t i = 0; i < reqnum; i++) {
        avg_rtt += rtts[i];
    }
    avg_rtt = avg_rtt / (float) reqnum;

    printf("Average RTT (us) %.6lf\n", avg_rtt);

    for (size_t i = reqnum % 10 + reqnum / 10; i < reqnum + 1;) {
        qsort(rtts, i + 1, sizeof(float), compare_float);
        printf("RPC 0-%ld CDF (RTT us) P50 %.2f P99 %.2f P99.9 %.2f, avg. length %.1f bytes\n",
            i, rtts[i/2], 
            rtts[99*i/100], 
            rtts[999*i/1000], 
            (double)reqlen
        );
        i += (reqnum / 10 > 0) ? reqnum / 10 : 1;
    }

    return 0;
}
