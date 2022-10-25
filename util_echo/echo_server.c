#include "echo.h"

const int recv_buflen = HOMA_MAX_MESSAGE_LENGTH;
unsigned char recv_buf[HOMA_MAX_MESSAGE_LENGTH];

void print_help_msg(char const *argv0) {
    fprintf(stdout, "usage %s port protocol [client1_ip] [client1_port] [client2_ip] [client2_port] \n"
    "client1_ip and client1_port are required for homals and homalsalt \n"
    "client2_ip and client2_port are required for homalsalt \n", argv0);
}

int homa_recv_reply(int sockfd) {
    struct sockaddr_in client_addr;
    size_t client_addrlen = sizeof(client_addr);
    uint64_t rpcid = 0;
    size_t reqlen = 0;
    int ret = 0;

    ret = homa_recv(sockfd, recv_buf, recv_buflen, HOMA_RECV_REQUEST, (struct sockaddr*)&client_addr, &client_addrlen, &rpcid, &reqlen);
    if (ret == -1) {
        printf("Couldn't receive Homa msg: %s\n", strerror(errno));
        return -1;
    }

#ifdef DEBUG
    char client_ip[INET_ADDRSTRLEN];

    if (inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN) == NULL) {
        printf("Couldn't convert client address to string (inet_ntop): %s\n", strerror(errno));
        return -1;
    }

    printf("Server recv (ip %s, port %hu, reqlen %ld, rpcid %ld): \n", client_ip, ntohs(client_addr.sin_port), reqlen, rpcid);
    for (size_t i = 0; i < reqlen; i++) {
        printf("%02hhX ", recv_buf[i]);
    }
    printf("\n");
#endif

    // exit(-1);

    ret = homa_reply(sockfd, recv_buf, reqlen, (struct sockaddr*)&client_addr, client_addrlen, rpcid);
    if (ret == -1) {
        printf("Couldn't send Homa msg: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

int main(int argc, char const *argv[])
{
    int port, protocol;
    int sockfd, sockfd_client, ret;
    struct sockaddr_in addr;
    size_t addrlen = sizeof(addr);

    if (argc < 3) {
        print_help_msg(argv[0]);
        return 1;
    }
    
    port = atoi(argv[1]);

    protocol = get_protocol(argv[2]);
    if (protocol == ECHO_PROTO_NUM) {
        print_protocol_names();        
        return 1;
    }

    memset(&addr, 0, addrlen);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY; 
    addr.sin_port = htons(port);

    if (protocol == ECHO_HOMA || protocol == ECHO_HOMALS || protocol == ECHO_HOMALSALT) {
        sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_HOMA);

        if (sockfd < 0) {
            printf("Couldn't open Homa socket: %s\n", strerror(errno));
            return 1;
        }
        if (bind(sockfd, (struct sockaddr*)&addr, addrlen) == -1) {
            printf("Couldn't bind Homa: %s\n", strerror(errno));
            return 1;
        }

        if (protocol == ECHO_HOMALS || protocol == ECHO_HOMALSALT) {
            struct homals_crypto_info homals_info_send, homals_info_read;

            if (argc < 5) {
                print_help_msg(argv[0]);
                return 1;
            }

            struct hostent *client_hostent = gethostbyname(argv[3]);
            if (client_hostent == NULL) {
                printf("Get client ip failed: %s\n", strerror(errno));
                return 1;
            }
            
            memcpy((char *)&homals_info_send.addr, (char *)client_hostent->h_addr, sizeof(homals_info_send.addr));
            memcpy((char *)&homals_info_read.addr, (char *)client_hostent->h_addr, sizeof(homals_info_read.addr));

            homals_info_send.port = htons(atoi(argv[4]));
            homals_info_read.port = htons(atoi(argv[4]));
            
            printf("homals_info_send.addr %x homals_info_send.port %x\n", htonl(homals_info_send.addr), (int)htons(homals_info_send.port));
            printf("homals_info_read.addr %x homals_info_read.port %x\n", htonl(homals_info_read.addr), (int)htons(homals_info_read.port));

            set_crypto_info(&(homals_info_send.crypto_info_aes_gcm_128), &(homals_info_read.crypto_info_aes_gcm_128), 1);

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

        // set alternative keys
        if (protocol == ECHO_HOMALSALT) {
            struct homals_crypto_info homals_info_send, homals_info_read;

            if (argc < 7) {
                print_help_msg(argv[0]);
                return 1;
            }

            struct hostent *client_hostent = gethostbyname(argv[5]);
            if (client_hostent == NULL) {
                printf("Get client ip failed: %s\n", strerror(errno));
                return 1;
            }
            
            memcpy((char *)&homals_info_send.addr, (char *)client_hostent->h_addr, sizeof(homals_info_send.addr));
            memcpy((char *)&homals_info_read.addr, (char *)client_hostent->h_addr, sizeof(homals_info_read.addr));

            homals_info_send.port = htons(atoi(argv[6]));
            homals_info_read.port = htons(atoi(argv[6]));
            
            printf("homals_info_send.addr %x homals_info_send.port %x\n", htonl(homals_info_send.addr), (int)htons(homals_info_send.port));
            printf("homals_info_read.addr %x homals_info_read.port %x\n", htonl(homals_info_read.addr), (int)htons(homals_info_read.port));

            set_crypto_info_alter(&(homals_info_send.crypto_info_aes_gcm_128), &(homals_info_read.crypto_info_aes_gcm_128), 1);

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

    while(1) {
        switch (protocol)
        {
        case ECHO_HOMA:
        case ECHO_HOMALS:
        case ECHO_HOMALSALT:
            ret = homa_recv_reply(sockfd);
            break;
        default:
            printf("unsupported protocol");
            exit(1);
        }
        if (ret == -1) {
            return 1;
        }
    }

    return 0;
}
