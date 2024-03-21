#ifndef PKT_DAEMON_H
#define PKT_DAEMON_H
#include "keytree.h"





// 数据包头结构体
typedef struct {
    uint8_t type;// 0查询 1加入 2离开 3广播BK 4更新
    int length;// data的长度，后续长度
} DataHeader;

typedef struct {
    DataHeader header;
    char data[MAX_MSG_LEN];
} Packet;

typedef struct {
    int front; // 队列头指针
    int rear;  // 队列尾指针
    int size;  // 当前队列中元素的数量
    Packet packets[MAX_MSG_SIZE];    
} PacketQueue;


extern PacketQueue *queue;
extern int tx_pkt_num;
extern int rx_pkt_num;
extern FILE *log_file;


extern int recv_socket;

#ifndef MY_MUTEX
#define MY_MUTEX
extern pthread_mutex_t mutex;
#endif


PacketQueue* initQueue();
void enqueue(Packet *packet);
Packet *dequeue();

char *createKeyTreePacket();
void parsePacket0(char *buffer); // 创建 server解析
void parsePacket3(char *buffer); // 加入广播BK  leaf
void parsePacket4(char *buffer); // 离开广播BK  leaf
void parsePacket5(char *buffer); // 更新广播BK  leaf
void parsePacket6(char *buffer); // 查询回复  server

void handlePacket(Packet *packet);


// 处理数据包：出队、判断数据包类型、不同的数据包类型执行不同的操作
#ifdef _WIN32
DWORD WINAPI processPackets();
#else
void *processPackets();
#endif

#endif /* UDP_PACKET_H */
