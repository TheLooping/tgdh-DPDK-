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
#include <linux/if.h>
#endif

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif

#ifdef _WIN32
WSADATA wsaData;
#endif



#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <openssl/bn.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>

#define TGDH_GROUP_NAME "tgdh_group"
#define TOKEN "test_token"

// keytree相关
#define TREE_HEIGHT 5
#define NODE_NUM 63 // 2^(TREE_HEIGHT + 1) - 1
#define BLIND_KEY_LEN 64 // 密钥长度 64 * 8 = 512 bits
#define KEY_LEN BLIND_KEY_LEN


// pkt_daemon相关
#define MAX_MSG_LEN 1024
#define MAX_PAYLOAD_LEN 1000 // 返回密钥树，截取单位
#define MAX_BUF_LEN 1200
#define MAX_MSG_SIZE 10
#define BUFSIZE 10240

// 定义服务器地址及端口 
// #define SERVER_IP6 "fe80::e643:4bff:fe65:3123"
// #define SERVER_IP6 "2400:dd01:1037:18:192:168:186:6"
#define SERVER_IP6 "2400:dd01:1037:25::1"
#define SERVER_PORT 8888
#define INTERFACE_NAME "eno4"

#define LOG_FILE_NAME "log_server.txt"

#endif