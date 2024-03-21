#include "pkt_daemon.h"

PacketQueue *initQueue()
{
    PacketQueue *queue = (PacketQueue *)malloc(sizeof(PacketQueue));
    queue->front = 0;
    queue->rear = -1;
    queue->size = 0;
    return queue;
}

// 判断队列是否为空
int isEmpty()
{
    return queue->size == 0;
}
// 判断队列是否已满
int isFull()
{
    return queue->size == MAX_MSG_SIZE;
}

// 入队操作
void enqueue(Packet *packet)
{
#ifdef _WIN32
    WaitForSingleObject(hMutex, INFINITE);
#else
    pthread_mutex_lock(&mutex);
#endif
    if (!isFull(queue))
    {
        queue->rear = (queue->rear + 1) % MAX_MSG_SIZE;
        memcpy(&(queue->packets[queue->rear]), packet, sizeof(Packet));
        queue->size++;
    }
    else
    {
        printf("Queue is full, cannot enqueue %d\n", queue->size);
    }
#ifdef _WIN32
    ReleaseMutex(hMutex);
#else
    pthread_mutex_unlock(&mutex);
#endif
}

// 出队操作
Packet *dequeue()
{
#ifdef _WIN32
    WaitForSingleObject(hMutex, INFINITE);
#else
    pthread_mutex_lock(&mutex);
#endif
    Packet *packet = NULL;
    if (!isEmpty())
    {
        packet = (Packet *)malloc(sizeof(Packet));
        memcpy(packet, &(queue->packets[queue->front]), sizeof(Packet));
        queue->front = (queue->front + 1) % MAX_MSG_SIZE;
        queue->size--;
    }

#ifdef _WIN32
    ReleaseMutex(hMutex);
#else
    pthread_mutex_unlock(&mutex);
    return packet;
#endif
}

void write_packet_to_file(char *payload, int len) {
    uint32_t i;
    for (i = 0; i < len; ++i) {
        // 打印每个字节的十六进制值
        fprintf(log_file, "%02X ", *((unsigned char *)payload + i));

        // 每行输出 16 个字节
        if ((i + 1) % 16 == 0)
            fprintf(log_file, "\n");
    }
    if (len % 16 != 0)
        fprintf(log_file, "\n");
}

char *createKeyTreePacket()
{
    char *buffer = malloc(BUFSIZE);
    memset(buffer, 0, BUFSIZE);
    DataHeader *header = (DataHeader *)buffer;
    int index = sizeof(DataHeader);
    memcpy(buffer + index, kt_ctx->group_name, sizeof(kt_ctx->group_name));
    index += 32;
    memcpy(buffer + index, &(kt_ctx->rounds), 4);
    index += 4;
    BN_bn2bin(kt_ctx->alpha, (unsigned char *)(buffer + index));
    index += KEY_LEN;
    BN_bn2bin(kt_ctx->p, (unsigned char *)(buffer + index));
    index += KEY_LEN;
    for (int i = 0; i < NODE_NUM; i++)
    {
        memcpy(buffer + index, &(kt_ctx->nodes[i].id), 4);
        index += 4;
        memcpy(buffer + index, &(kt_ctx->nodes[i].flag), 4);
        index += 4;
        memcpy(buffer + index, &(kt_ctx->nodes[i].is_update), 4);
        index += 4;
        memcpy(buffer + index, &(kt_ctx->nodes[i].addr), sizeof(struct sockaddr_in6));
        index += sizeof(struct sockaddr_in6);
        if (i == 0)
        {
            memset(buffer + index, 0, KEY_LEN);
        }
        else if(kt_ctx->nodes[i].flag != 0){
            BN_bn2bin(kt_ctx->nodes[i].blind_key,  (unsigned char *)(buffer + index));
        }
        else
        {
            memset(buffer + index, 0, KEY_LEN);
        }
        index += KEY_LEN;

    }
    header->length = index - sizeof(DataHeader);
    return buffer;
};

// 解析创建请求数据包(type 0) create to server
void parsePacket0(char *buffer)
{
    DataHeader *header = (DataHeader *)buffer;
    if (header->type != 0)
    {
        printf("Error: parseCreatePacket failed: header->type\n");
        return;
    }
    int index = sizeof(DataHeader);
    // groupname 32bytes
    memcpy(kt_ctx->group_name, buffer + index, 32);
    index += 32;
    if (strcmp(kt_ctx->group_name, TGDH_GROUP_NAME) != 0)
    {
        printf("Error: parseCreatePacket failed: kt_ctx->group_name\n");
        return;
    }
    // rounds 4bytes
    memcpy(&(kt_ctx->rounds), buffer + index, 4);
    index += 4;
    // alpha 512bits
    kt_ctx->alpha = BN_bin2bn((unsigned char *)(buffer + index), KEY_LEN, NULL);
    index += KEY_LEN;
    // p 512bits
    kt_ctx->p = BN_bin2bn( (unsigned char *)(buffer + index), KEY_LEN, NULL);
    index += KEY_LEN;
    // root node
    memcpy(&(kt_ctx->nodes[0].id), buffer + index, 4);
    index += 4;
    memcpy(&(kt_ctx->nodes[0].flag), buffer + index, 4);
    index += 4;
    memcpy(&(kt_ctx->nodes[0].is_update), buffer + index, 4);
    index += 4;
    memcpy(&(kt_ctx->nodes[0].addr), buffer + index, sizeof(struct sockaddr_in6));
    index += sizeof(struct sockaddr_in6);
    // 验证长度
    if (index != header->length + sizeof(DataHeader))
        printf("Error: parseCreatePacket failed: index: %d; header->length %d; sizeof(DataHeader):%ld\n",index, header->length, sizeof(DataHeader));
}


// 解析加入的BK更新信息(type 3) sponsor to all
// dataheader + keytree_node join_node + n * (nodeID + blinded_key)
void parsePacket3(char *buffer)
{
    DataHeader *header = (DataHeader *)buffer;
    if (header->type != 3)
    {
        printf("Error: parseUpdateBK failed.\n");
        return;
    }
    int index = sizeof(DataHeader);
    // keytree_node
    keytree_node *join_node = (keytree_node *)malloc(sizeof(keytree_node));
    memcpy(&(join_node->id), buffer + index, 4);
    index += 4;
    memcpy(&(join_node->flag), buffer + index, 4);
    index += 4;
    memcpy(&(join_node->is_update), buffer + index, 4);
    index += 4;
    memcpy(&(join_node->addr), buffer + index, sizeof(struct sockaddr_in6));
    index += sizeof(struct sockaddr_in6);
    join_node->blind_key = BN_bin2bn((unsigned char *)(buffer + index), KEY_LEN, NULL);
    index += KEY_LEN;

    // 加入kt_ctx
    nodeJoinTree(join_node);

    int id = 0;
    BIGNUM *blinded_key = BN_new();
    // 解析更新的BK信息
    int total_len = header->length + sizeof(DataHeader);
    while (index < total_len)
    {
        memcpy(&id, buffer + index, 4);
        index += 4;
        blinded_key = BN_bin2bn((unsigned char *)(buffer + index), KEY_LEN, NULL);
        updateNodeKey(id, blinded_key);
        index += KEY_LEN;
    }

    // 验证长度
    if (index != header->length + sizeof(DataHeader))
        printf("Error: parseUpdateBK failed.\n");

    // 释放资源
    BN_free(blinded_key);
}

// 解析离开的BK更新信息(type 4) sponsor to all
// dataheader + leave_node_id + n * (nodeID + blinded_key)
void parsePacket4(char *buffer)
{
    DataHeader *header = (DataHeader *)buffer;
    if (header->type != 4)
    {
        printf("Error: parseLeaveBK failed.\n");
    }
    int index = sizeof(DataHeader);
    int leave_node_id = 0;
    memcpy(&leave_node_id, buffer + index, 4);
    index += 4;
    
    nodeLeaveTree(leave_node_id);
    int id = 0;
    BIGNUM *blinded_key = BN_new();
    // 解析更新的BK信息
    while (index < header->length + sizeof(DataHeader))
    {
        memcpy(&id, buffer + index, 4);
        index += 4;
        blinded_key = BN_bin2bn((unsigned char *)(buffer + index), KEY_LEN, NULL);
        updateNodeKey(id, blinded_key);
        index += KEY_LEN;
    }
    // 验证长度
    if (index != header->length + sizeof(DataHeader))
        printf("Error: parseLeaveBK failed.\n");

    // 释放资源
    BN_free(blinded_key);
}

// 解析更新的BK信息(type 5) sponsor to all
// dataheader + n * (nodeID + blinded_key)
void parsePacket5(char *buffer)
{
    DataHeader *header = (DataHeader *)buffer;
    if (header->type != 5)
    {
        printf("Error: parseUpdateBK failed.\n");
        return;
    }
    int index = sizeof(DataHeader);
    int id = 0;
    BIGNUM *blinded_key = BN_new();
    // 解析更新的BK信息
    while (index < header->length + sizeof(DataHeader))
    {
        memcpy(&id, buffer + index, 4);
        index += 4;
        blinded_key = BN_bin2bn((unsigned char *)(buffer + index), KEY_LEN, NULL);
        updateNodeKey(id, blinded_key);
        index += KEY_LEN;
    }
    // 验证长度
    if (index != header->length + sizeof(DataHeader))
        printf("Error: parseUpdateBK failed.\n");

    // 释放资源
    BN_free(blinded_key);
}

// 解析查询请求数据包，返回查询结果
void parsePacket6(char *buffer)
{
    sleep(1);
    Packet *packet = (Packet *)buffer;
    if (packet->header.type == 6)
    {
        if (memcmp(packet->data, TGDH_GROUP_NAME, sizeof(TGDH_GROUP_NAME)) == 0)
        {
            if (memcmp(packet->data + 32, TOKEN, sizeof(TOKEN)) == 0)
            {
                // 解析client addr
                struct sockaddr_in6 client_addr;
                memcpy(&client_addr, packet->data + 64, sizeof(struct sockaddr_in6));                

                char *response = createKeyTreePacket();
                DataHeader *header = (DataHeader *)response;
                int len = header->length + sizeof(DataHeader);
                int count = len / MAX_PAYLOAD_LEN + 1;
                if (len % MAX_PAYLOAD_LEN == 0)
                {
                    count--;
                }
                char *payload_buffer = (char *)malloc(MAX_BUF_LEN);
                memset(payload_buffer, 0, MAX_BUF_LEN);
                int offset;
                
                for (int i = 0; i < count; i++)
                {
                    int payload_len = MAX_PAYLOAD_LEN;
                    if (i == count - 1)
                    {
                        payload_len = len - i * MAX_PAYLOAD_LEN;
                    }
                    char *payload = response + i * MAX_PAYLOAD_LEN;
                    // 构造ipv6/udp数据包:type 6 ,index / counts , payload(MAX_PAYLOAD_LEN 1000)
                    offset = 0;
                    DataHeader *tmp_header = (DataHeader *)payload_buffer;
                    tmp_header->type = 6;
                    offset += sizeof(DataHeader);
                    memcpy(payload_buffer + offset, &i, 4);
                    offset += 4;
                    memcpy(payload_buffer + offset, &count, 4);
                    offset += 4;
                    memcpy(payload_buffer + offset, payload, payload_len);
                    offset += payload_len;
                    tmp_header->length = offset - sizeof(DataHeader);
                    sendto(recv_socket, payload_buffer, offset, 0, (struct sockaddr *)&client_addr, sizeof(client_addr));
                    fprintf_log(log_file, "send back the %d/%d part of kt_ctx, length:%d\n", i + 1, count, offset);
                    memset(payload_buffer, 0, MAX_BUF_LEN);
                }
                
                fprintf_log(log_file, "send back the kt_ctx completed\n");
                free(payload_buffer);
                free(response);
                return;
            }
            fprintf_log(log_file, "Invalid query: TOKEN wrong\n");
            return;
        }
        fprintf_log(log_file, "Invalid query: TGDH_GROUP_NAME wrong\n");
        return;
    }
}


void handlePacket(Packet *packet)
{
    fprintf(log_file,"\n\n");
    fprintf_log(log_file,"parsePacket%d.\n",packet->header.type);
    // 处理数据包，判断数据包类型，不同的数据包类型执行不同的操作
    if (packet->header.type == 0)
    {
        // 创建 (只有server节点才会收到创建包)
        parsePacket0((char *)packet);
        fprintf_log(log_file, "receive udp(type:0): receive a create infomatioin\n");
    }
    else if (packet->header.type == 1)
    {
        fprintf_log(log_file, "wrong! server should not receive a join request\n");        
    }
    else if (packet->header.type == 2)
    {
        fprintf_log(log_file, "wrong! server should not receive a leave request\n");
    }
    else if (packet->header.type == 3)
    {
        // 收到sponsor节点的加入广播包
        parsePacket3((char *)packet);
        //new :delete updateGroupKey
        fprintf_log(log_file, "receive udp (type:3): sponsor to all member, a node join the group\n");
    }
    else if (packet->header.type == 4)
    {
        // 收到sponsor节点的离开广播包
        parsePacket4((char *)packet);
        //new :delete updateGroupKey
        int *leave_node_id = (int *)((char *)packet + sizeof(DataHeader));
        fprintf_log(log_file, "receive udp (type:4): sponsor to all member, node %d leave the group\n", *leave_node_id);
    }
    else if (packet->header.type == 5)
    {
        // 收到sponsor节点的更新广播包
        parsePacket5((char *)packet);
        //new :delete updateGroupKey
        fprintf_log(log_file, "receive udp (type:5): sponsor to all member, a node update its BK\n");
    }
    else if (packet->header.type == 6)
    {
        fprintf_log(log_file, "receive udp (rx_pkt_num:%d ;type:6): receive a query request\n", rx_pkt_num);
        // 收到查询请求
        parsePacket6((char *)packet);
    }    
    else
    {
        fprintf_log(log_file, "Error: unknown packet type.\n");
    }
    if (packet->header.type < 6 && packet->header.type >= 0){
        kt_ctx->rounds++;
        printfTree();
    }
}


// 处理数据包：出队、调用handlePacket函数
#ifdef _WIN32
DWORD WINAPI processPackets()
{
#else
void *processPackets()
{
#endif   
    while (1)
    {
        usleep(100000); // 100ms
        Packet *packet = dequeue();
        // 处理数据包，判断数据包类型，不同的数据包类型执行不同的操作
        if (packet != NULL)
        {
            handlePacket(packet);
            free(packet);
        }
    }
}
