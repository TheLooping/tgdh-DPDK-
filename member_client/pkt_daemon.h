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
extern struct rte_pcapng *pcapng;




extern pthread_mutex_t mutex;
extern rte_spinlock_t lock;
extern struct rte_mempool *mbuf_pool;



PacketQueue* initQueue();
void enqueue(Packet *packet);
Packet *dequeue();

Packet *createQueryPacket(); // TCP 0 查询 to server

Packet *createCreatePacket0(); // 0 创建时通告 to server
Packet *createJoinPacket1(); // 1 加入 to sponsor
Packet *createLeavePacket2(); // 2 离开 to sponsor
Packet *createUpdatePacket3(); // 3 加入广播BK to leaf
Packet *createUpdatePacket4(int nodeID); // 4 离开广播BK to leaf
Packet *createUpdatePacket5(); // 5 更新广播BK to leaf
Packet *createQueryPacket6();
char *createKeyTreePacket();
void parseKeyTree(char *buffer); // TCP 解析服务器的响应结果
void parsePacket0(char *buffer); // 创建 server解析
void parsePacket1(char *buffer); // 加入 sponsor
int parsePacket2(char *buffer); // 离开 sponsor
void parsePacket3(char *buffer); // 加入广播BK  leaf
void parsePacket4(char *buffer); // 离开广播BK  leaf
void parsePacket5(char *buffer); // 更新广播BK  leaf
void parsePacket6(char *buffer);


void handlePacket(Packet *packet);


// 处理数据包：出队、判断数据包类型、不同的数据包类型执行不同的操作
int processPackets(void *arg);


// 向服务器节点发送tcp请求，将回复的信息存储在buffer
void query2server();

// 向对应ID的节点发送udp报文 （仅发送）
void send2node(Packet *packet, int nodeID);

// 向服务器节点发送udp报文 （仅发送）
void send2server(Packet *packet);

// 向所有叶子节点发送广播报文 （仅发送）
void broadcast2leaf(Packet *packet);



struct rte_mbuf *construct_ipv6_udp_packet(Packet *packet, struct sockaddr_in6 src_addr, struct sockaddr_in6 dst_addr);
int send_packet(struct rte_mbuf *packet);
struct rte_mbuf *construct_ipv6_udp_packet_6(struct sockaddr_in6 src_addr, struct sockaddr_in6 dst_addr, int index, int counts, char *payload, int payload_len);





#endif /* UDP_PACKET_H */
