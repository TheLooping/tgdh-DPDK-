#ifndef _MYINCLUDE_H
#define _MYINCLUDE_H

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif





#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <openssl/bn.h>
#include <stdarg.h>
#include <time.h>
#include <inttypes.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_pcapng.h> 
#include <rte_errno.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 16

#define TGDH_GROUP_NAME "tgdh_group"
#define TOKEN "test_token"





// keytree
#define TREE_HEIGHT 5
#define NODE_NUM 63 // 2^(TREE_HEIGHT + 1) - 1

#define BLIND_KEY_LEN 64
#define KEY_LEN BLIND_KEY_LEN



// pkt_daemon
#define MAX_MSG_LEN 1024
#define MAX_MSG_SIZE 10
#define BUFSIZE 10240

#define SERVER_MAC "\xe4\x43\x4b\x65\x31\x23"
#define SERVER_IP6 "2400:dd01:1037:25::1"
#define SERVER_PORT 8888



#define MAC_ADDRESS_NODE0 "\xf8\xf2\x1e\x8f\xcb\x10"
#define IP_ADDRESS_NODE0 "2400:dd01:1037:25::2"

#define MAC_ADDRESS_NODE1 "\xf8\xf2\x1e\x8f\xcb\x11"
#define IP_ADDRESS_NODE1 "2400:dd01:1037:25::3"


#define MAC_ADDRESS_STR MAC_ADDRESS_NODE0
#define IP_ADDRESS_STR IP_ADDRESS_NODE0
#define TGDH_PORT 8888


#define PORT_ID 0  // 发送数据包的端口 ID


#define MAX_PAYLOAD_LEN 1000


// key
#define ENCRYPTION_KEY_DIR "encryption_key"
#define STATUS_FILE "status.bin"

#define KEY_MAX_SIZE 100


#endif