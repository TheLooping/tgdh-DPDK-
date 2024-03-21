#ifndef KEYTREE_H
#define KEYTREE_H

#include "myinclude.h"




// 节点结构：ID（从1开始），标志位（0空 1node 2leaf），密钥轮次，是否更新，盲化密钥
typedef struct keytree_node {
    int id;
    int flag; // 0空 1node 2leaf
    int is_update;
    // 地址、端口
    // unsigned char mac[ETH_ALEN];
    struct sockaddr_in6 addr; // 只有当flag=2时才有意义
    BIGNUM *blind_key;  
} keytree_node;

// 上下文结构：参数，根节点盲化密钥（群组），树结构及盲化密钥
typedef struct keytree_context {
    char group_name[32];
    int rounds;
    BIGNUM *alpha;
    BIGNUM *p;
    keytree_node nodes[NODE_NUM];  
} keytree_context;

// 自己的节点ID，自己的密钥
typedef struct keytree_self {
    int id;
    BIGNUM *self_key;
    struct sockaddr_in6 addr;
} keytree_self;


typedef struct {
    int round;
    char key[KEY_LEN];
} rounds_key;
typedef struct {
    int max_size;
    int min_index;
    int max_index;
    int counts;
} key_status;


extern keytree_context *kt_ctx;
extern keytree_self *key_self;

static time_t rawtime;
static struct tm *timeinfo;
static char time_str[80];
static struct timespec ts;
static long milliseconds;

extern FILE *log_file;
void fprintf_log(FILE *file, const char *format, ...);

int findParentID(int nodeID);
int findSiblingID(int nodeID);
int findRightChildID(int nodeID);

int findSubTreeID(int root, int level, int index);

// 计算离开sponsor：根据节点ID查找兄弟节点的子树中最低层的最右侧成员节点ID
int findLeaveSponsorID(int nodeID);

// 计算加入sponsor：查找根节点的树中最低层的最右侧成员节点ID
int findJoinSponsorID(); 


// 根据key生成blind_key
BIGNUM *generateBlindKey(BIGNUM *key, BIGNUM *alpha, BIGNUM *p);

// 根据节点的key和兄弟节点的blind_key生成父节点的key
BIGNUM *generateParentKey(BIGNUM *self_key, BIGNUM *sibling_blind_key, BIGNUM *p);

// 更新群组密钥 上下文信息、根节点信息、节点状态
void updateGroupKey();


// 根据前后ID移动节点
void moveNode(int oldID, int newID);

// 根据前后ID移动子树
void moveSubTree(int oldID, int newID);

// 更新节点的key和blind_key
void updateNodeKey(int nodeID, BIGNUM *blind_key);

// 更新路径上的节点的blind_key
void updatePathKey(int nodeID, BIGNUM *key);

// 新节点加入
void joinTree(keytree_node *node, BIGNUM *key);

// 节点离开
void leaveTree(int nodeID, BIGNUM *key);


// 节点加入：所有节点调用此函数
void nodeJoinTree(keytree_node *node);

// 节点离开：所有节点调用此函数
void nodeLeaveTree(int nodeID);

void printfTree();

void key_dir_init();
void write_status(key_status ks);
key_status read_status();
int write_key();
rounds_key *read_key(int rounds);

#endif // KEYTREE_H