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
    rte_spinlock_lock(&lock);
    if (!isFull(queue))
    {
        queue->rear = (queue->rear + 1) % MAX_MSG_SIZE;
        memcpy(&(queue->packets[queue->rear]), packet, sizeof(Packet));
        queue->size++;
    }
    else
    {
        fprintf_log(log_file, "Queue is full, cannot enqueue %d\n", queue->size);
    }

    rte_spinlock_unlock(&lock);
}

// 出队操作
Packet *dequeue()
{

    rte_spinlock_lock(&lock);

    Packet *packet = NULL;
    if (!isEmpty())
    {
        packet = (Packet *)malloc(sizeof(Packet));
        memcpy(packet, &(queue->packets[queue->front]), sizeof(Packet));
        queue->front = (queue->front + 1) % MAX_MSG_SIZE;
        queue->size--;
    }

    rte_spinlock_unlock(&lock);
    return packet;
}

// 构造查询数据包 header + groupname(32bytes) + token(32bytes)
Packet *createQueryPacket()
{
    Packet *packet = (Packet *)malloc(sizeof(Packet));
    memset(packet, 0, sizeof(Packet));
    packet->header.type = 0;
    int index = 0;
    // groupname 32bytes
    memcpy(packet->data + index, TGDH_GROUP_NAME, sizeof(TGDH_GROUP_NAME));
    index += 32;
    // token 32bytes
    memcpy(packet->data + index, TOKEN, sizeof(TOKEN));
    index += 32;
    packet->header.length = index;

    return packet;
}

// 构造创建数据包 header + groupname(32bytes) + rounds(4bytes) + alpha(512bits) + p(512bits) + root_node(nodeID(4bytes) + flag(4bytes) + is_update(4bytes) + sockaddr_in(16bytes))
Packet *createCreatePacket0()
{
    Packet *packet = (Packet *)malloc(sizeof(Packet));
    memset(packet, 0, sizeof(Packet));
    packet->header.type = 0;
    // groupname 32bytes
    int index = 0;
    memcpy(packet->data, TGDH_GROUP_NAME, sizeof(TGDH_GROUP_NAME));
    index += 32;
    // rounds 4bytes
    memcpy(packet->data + index, &(kt_ctx->rounds), sizeof(kt_ctx->rounds));
    index += 4;
    // alpha 512bits
    BN_bn2bin(kt_ctx->alpha, packet->data + index);
    index += KEY_LEN;
    // p 512bits
    BN_bn2bin(kt_ctx->p, packet->data + index);
    index += KEY_LEN;
    // root node
    memcpy(packet->data + index, &(kt_ctx->nodes[0].id), 4);
    index += 4;
    memcpy(packet->data + index, &(kt_ctx->nodes[0].flag), 4);
    index += 4;
    memcpy(packet->data + index, &(kt_ctx->nodes[0].is_update), 4);
    index += 4;
    memcpy(packet->data + index, &(kt_ctx->nodes[0].addr), sizeof(struct sockaddr_in6));
    index += sizeof(struct sockaddr_in6);
    packet->header.length = index;

    return packet;
}

// 构造加入数据包 header + groupname(32bytes) + sockaddr_in6(28bytes) + blinded key(512bytes)
Packet *createJoinPacket1()
{
    Packet *packet = (Packet *)malloc(sizeof(Packet));
    memset(packet, 0, sizeof(Packet));
    packet->header.type = 1;
    int index = 0;
    // groupname 32bytes
    memcpy(packet->data + index, TGDH_GROUP_NAME, sizeof(TGDH_GROUP_NAME));
    index += 32;
    // sockaddr_in 16bytes
    memcpy(packet->data + index, &(key_self->addr), sizeof(struct sockaddr_in6));
    index += sizeof(struct sockaddr_in6);
    // blinded key 512bits
    // 计算blinded key
    BIGNUM *blinded_key = BN_new();
    blinded_key = generateBlindKey(key_self->self_key, kt_ctx->alpha, kt_ctx->p);
    BN_bn2bin(blinded_key, packet->data + index);
    index += BLIND_KEY_LEN;
    packet->header.length = index;
    BN_free(blinded_key);

    return packet;
}

// 构造离开数据包 header + groupname(32bytes) + nodeID(4bytes)
Packet *createLeavePacket2()
{
    Packet *packet = (Packet *)malloc(sizeof(Packet));
    memset(packet, 0, sizeof(Packet));
    packet->header.type = 2;
    int index = 0;
    // groupname 32bytes
    memcpy(packet->data + index, TGDH_GROUP_NAME, sizeof(TGDH_GROUP_NAME));
    index += 32;
    // nodeID 4bytes
    memcpy(packet->data + index, &(key_self->id), 4);
    index += 4;
    packet->header.length = index;

    return packet;
}

// 构造加入更新数据包 header + join_node * (nodeID(4bytes) + blinded key(512bits))
Packet *createUpdatePacket3()
{
    Packet *packet = (Packet *)malloc(sizeof(Packet));
    memset(packet, 0, sizeof(Packet));
    packet->header.type = 3;
    // 更新路径上的节点的blind_key 已更新(prasePacket1)

    // join节点；递归查找父节点 将更新的blinded key存储在packet中
    int index = 0;
    // 兄弟节点是join节点
    int id = findSiblingID(key_self->id);
    memcpy(packet->data + index, &(kt_ctx->nodes[id].id), 4);
    index += 4;
    memcpy(packet->data + index, &(kt_ctx->nodes[id].flag), 4);
    index += 4;
    memcpy(packet->data + index, &(kt_ctx->nodes[id].is_update), 4);
    index += 4;
    memcpy(packet->data + index, &(kt_ctx->nodes[id].addr), sizeof(struct sockaddr_in6));
    index += sizeof(struct sockaddr_in6);
    BN_bn2bin(kt_ctx->nodes[id].blind_key, packet->data + index);
    index += BLIND_KEY_LEN;

    id = key_self->id;
    while (id != 0)
    {
        memcpy(packet->data + index, &id, 4);
        index += 4;
        BN_bn2bin(kt_ctx->nodes[id].blind_key, packet->data + index);
        index += BLIND_KEY_LEN;
        id = findParentID(id);
        kt_ctx->nodes[id].is_update = 0; // 复位
    }
    packet->header.length = index;

    return packet;
}
// 构造离开数据包 header + leave_node_id + n * (nodeID(4bytes) + blinded key(512bits))
Packet *createUpdatePacket4(int nodeID)
{
    Packet *packet = (Packet *)malloc(sizeof(Packet));
    memset(packet, 0, sizeof(Packet));
    packet->header.type = 4;
    // 离开节点；递归查找父节点 将更新的blinded key存储在packet中
    int index = 0;
    memcpy(packet->data + index, &nodeID, 4);
    index += 4;
    // 更新路径上的节点的blind_key 已更新(prasePacket2)
    int id = key_self->id;
    while (id != 0)
    {
        memcpy(packet->data + index, &id, 4);
        index += 4;
        BN_bn2bin(kt_ctx->nodes[id].blind_key, packet->data + index);
        index += BLIND_KEY_LEN;
        id = findParentID(id);
        kt_ctx->nodes[id].is_update = 0; // 复位
    }
    packet->header.length = index;

    return packet;
}
// 构造更新数据包 header + n * (nodeID(4bytes) + blinded key(512bits))
Packet *createUpdatePacket5()
{
    Packet *packet = (Packet *)malloc(sizeof(Packet));
    memset(packet, 0, sizeof(Packet));
    packet->header.type = 5;
    // 递归查找父节点 将更新的blinded key存储在packet中
    int index = 0;
    int id = key_self->id;
    while (id != 0)
    {
        memcpy(packet->data + index, &id, 4);
        index += 4;
        BN_bn2bin(kt_ctx->nodes[id].blind_key, packet->data + index);
        index += BLIND_KEY_LEN;
        id = findParentID(id);
    }
    packet->header.length = index;

    return packet;
}

// 创建加入查询数据包(type 6) join_node to server : header + groupname(32bytes) + token(32bytes) + self_addr(28bytes)
Packet *createQueryPacket6()
{
    Packet *packet = (Packet *)malloc(sizeof(Packet));
    memset(packet, 0, sizeof(Packet));
    packet->header.type = 6;
    int index = 0;
    // groupname 32bytes
    memcpy(packet->data + index, TGDH_GROUP_NAME, sizeof(TGDH_GROUP_NAME));
    index += 32;
    // token 32bytes
    memcpy(packet->data + index, TOKEN, sizeof(TOKEN));
    index += 32;
    // self_addr 28bytes
    memcpy(packet->data + index, &(key_self->addr), sizeof(struct sockaddr_in6));
    index += sizeof(struct sockaddr_in6);
    packet->header.length = index;

    return packet;
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
    BN_bn2bin(kt_ctx->alpha, buffer + index);
    index += KEY_LEN;
    BN_bn2bin(kt_ctx->p, buffer + index);
    index += KEY_LEN;
    int i;
    for (i = 0; i < NODE_NUM; i++)
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
        else if (kt_ctx->nodes[i].flag != 0)
        {
            BN_bn2bin(kt_ctx->nodes[i].blind_key, buffer + index);
        }
        else
        {
            memset(buffer + index, 0, KEY_LEN);
        }
        index += KEY_LEN;
    }
    header->length = index - sizeof(DataHeader);
};

// 解析密钥树信息 server to join_node
void parseKeyTree(char *buffer)
{
    DataHeader *header = (DataHeader *)buffer;
    int index = sizeof(DataHeader);
    // 解析密钥树信息
    memcpy(kt_ctx->group_name, buffer + index, 32);
    index += 32;
    memcpy(&(kt_ctx->rounds), buffer + index, 4);
    index += 4;
    // kt_ctx->alpha = BN_bin2bn(buffer + index, KEY_LEN, NULL);
    BN_set_word(kt_ctx->alpha, 2); // 选择一个常见的底数，也可以是其他值
    fprintf_log(log_file, "TODO: 需要重新改回来 \n");

    index += KEY_LEN;
    kt_ctx->p = BN_bin2bn(buffer + index, KEY_LEN, NULL);
    index += KEY_LEN;
    int i;
    for (i = 0; i < NODE_NUM; i++)
    {
        memcpy(&(kt_ctx->nodes[i].id), buffer + index, 4);
        index += 4;
        memcpy(&(kt_ctx->nodes[i].flag), buffer + index, 4);
        index += 4;
        memcpy(&(kt_ctx->nodes[i].is_update), buffer + index, 4);
        index += 4;
        memcpy(&(kt_ctx->nodes[i].addr), buffer + index, sizeof(struct sockaddr_in6));
        index += sizeof(struct sockaddr_in6);
        if (i == 0)
        {
            kt_ctx->nodes[i].blind_key = BN_new();
        }
        else if (kt_ctx->nodes[i].flag != 0)
        {
            kt_ctx->nodes[i].blind_key = BN_bin2bn(buffer + index, KEY_LEN, NULL);
        }
        index += KEY_LEN;
    }
    // 验证长度
    if (index != header->length + sizeof(DataHeader))
        fprintf_log(log_file, "Error: parseKeyTree failed. index:%d  header->length:%d  sizeof(DataHeader):%d \n",index,header->length, sizeof(DataHeader));

}

// 解析创建请求数据包(type 0) create to server
void parsePacket0(char *buffer)
{
    DataHeader *header = (DataHeader *)buffer;
    if (header->type != 0)
    {
        fprintf_log(log_file, "Error: parseCreatePacket failed.\n");
        return;
    }
    int index = sizeof(DataHeader);
    // groupname 32bytes
    memcpy(kt_ctx->group_name, buffer + index, 32);
    index += 32;
    if (strcmp(kt_ctx->group_name, TGDH_GROUP_NAME) != 0)
    {
        fprintf_log(log_file, "Error: parseCreatePacket failed.\n");
        return;
    }
    // rounds 4bytes
    memcpy(&(kt_ctx->rounds), buffer + index, 4);
    index += 4;
    // alpha 512bits
    kt_ctx->alpha = BN_bin2bn(buffer + index, KEY_LEN, NULL);
    index += KEY_LEN;
    // p 512bits
    kt_ctx->p = BN_bin2bn(buffer + index, KEY_LEN, NULL);
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
        fprintf_log(log_file, "Error: parseCreatePacket failed.\n");
}

// 解析加入请求数据包(type 1) join_node to sponsor
void parsePacket1(char *buffer)
{

    DataHeader *header = (DataHeader *)buffer;
    if (header->type != 1)
    {
        fprintf_log(log_file, "Error: parseJoinPacket failed.\n");
        return;
    }
    int index = sizeof(DataHeader);

    // groupname 32bytes
    char groupname[32];
    memcpy(groupname, buffer + index, 32);
    index += 32;

    if (strcmp(groupname, TGDH_GROUP_NAME) != 0)
    {
        fprintf_log(log_file, "Error: parseJoinPacket failed.\n");
        return;
    }
    // sockaddr_in 、blinded key
    keytree_node *node = (keytree_node *)malloc(sizeof(keytree_node));
    memcpy(&(node->addr), buffer + index, sizeof(struct sockaddr_in6));
    index += sizeof(struct sockaddr_in6);
    node->blind_key = BN_bin2bn(buffer + index, KEY_LEN, NULL);
    index += KEY_LEN;
    // 加入kt_ctx, 更新路径上的节点的blind_key
    joinTree(node, key_self->self_key);

    // 验证长度
    if (index != header->length + sizeof(DataHeader))
    {
        fprintf_log(log_file, "Error: parseJoinPacket failed.\n");
    }
}

// 解析离开请求数据包(type 2) leave_node to sponsor
int parsePacket2(char *buffer)
{
    DataHeader *header = (DataHeader *)buffer;
    if (header->type != 2)
    {
        fprintf_log(log_file, "Error: parseLeavePacket failed.\n");
        return -1;
    }
    int index = sizeof(DataHeader);
    // groupname 32bytes
    char groupname[32];
    memcpy(groupname, buffer + index, sizeof(TGDH_GROUP_NAME));
    index += 32;
    if (strcmp(groupname, TGDH_GROUP_NAME) != 0)
    {
        fprintf_log(log_file, "Error: parseLeavePacket failed.\n");
        return -1;
    }
    // nodeID 4bytes
    int nodeID = 0;
    memcpy(&nodeID, buffer + index, 4);
    index += 4;
    // 计算离开sponsor
    int leaveSponsorID = findLeaveSponsorID(nodeID);
    if (leaveSponsorID != key_self->id)
    {
        fprintf_log(log_file, "Error: parseLeavePacket failed.\n");
        return -1;
    }
    // 离开sponsor
    leaveTree(nodeID, key_self->self_key);
    // 验证长度
    if (index != header->length + sizeof(DataHeader))
        fprintf_log(log_file, "Error: parseLeavePacket failed.\n");
    // 释放资源
    return nodeID;
}

// 解析加入的BK更新信息(type 3) sponsor to all
// dataheader + keytree_node join_node + n * (nodeID + blinded_key)
void parsePacket3(char *buffer)
{
    DataHeader *header = (DataHeader *)buffer;
    if (header->type != 3)
    {
        fprintf_log(log_file, "Error: parseUpdateBK failed.\n");
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
    join_node->blind_key = BN_bin2bn(buffer + index, KEY_LEN, NULL);
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
        blinded_key = BN_bin2bn(buffer + index, KEY_LEN, NULL);
        updateNodeKey(id, blinded_key);
        index += KEY_LEN;
    }

    // 验证长度
    if (index != header->length + sizeof(DataHeader))
        fprintf_log(log_file, "Error: parseUpdateBK failed.\n");

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
        fprintf_log(log_file, "Error: parseLeaveBK failed.\n");
        return;
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
        blinded_key = BN_bin2bn(buffer + index, KEY_LEN, NULL);
        updateNodeKey(id, blinded_key);
        index += KEY_LEN;
        fprintf_log(log_file, "update node %d\n", id);
    }
    // 验证长度
    if (index != header->length + sizeof(DataHeader))
        fprintf_log(log_file, "Error: parseLeaveBK failed.\n");

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
        fprintf_log(log_file, "Error: parseUpdateBK failed.\n");
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
        blinded_key = BN_bin2bn(buffer + index, KEY_LEN, NULL);
        updateNodeKey(id, blinded_key);
        index += KEY_LEN;
    }
    // 验证长度
    if (index != header->length + sizeof(DataHeader))
        fprintf_log(log_file, "Error: parseUpdateBK failed.\n");

    // 释放资源
    BN_free(blinded_key);
}

// 解析查询请求数据包，返回查询结果
void parsePacket6(char *buffer)
{
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
                // 自己的(server)addr
                struct sockaddr_in6 srv_addr;
                memset(&srv_addr, 0, sizeof(struct sockaddr_in6));
                srv_addr.sin6_family = AF_INET6;
                srv_addr.sin6_port = htons(SERVER_PORT);
                inet_pton(AF_INET6, SERVER_IP6, &(srv_addr.sin6_addr));

                char *response = createKeyTreePacket();
                DataHeader *header = (DataHeader *)response;
                int len = header->length + sizeof(DataHeader);
                int count = len / MAX_PAYLOAD_LEN + 1;
                if (len % MAX_PAYLOAD_LEN == 0)
                {
                    count--;
                }
                int i;
                for (i = 0; i < count; i++)
                {
                    int payload_len = MAX_PAYLOAD_LEN;
                    if (i == count - 1)
                    {
                        payload_len = len - i * MAX_PAYLOAD_LEN;
                    }
                    char *payload = response + i * MAX_PAYLOAD_LEN;
                    // 构造ipv6、udp数据包:type 6 ,index / counts , payload(MAX_PAYLOAD_LEN 1000)
                    struct rte_mbuf *mbuf = construct_ipv6_udp_packet_6(srv_addr, client_addr, i + 1, count, payload, payload_len);
                    // 发送数据包
                    send_packet(mbuf);
                    fprintf_log(log_file, "send back the %d/%d part of kt_ctx\n", i + 1, count);
                }

                fprintf_log(log_file, "send back the kt_ctx completed\n");
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
    // fprintf(log_file,"\n");

    // 处理数据包，判断数据包类型，不同的数据包类型执行不同的操作
    if (packet->header.type == 0)
    {
        fprintf_log(log_file, "parsePacket0.\n");
        fprintf_log(log_file, "receive udp(rx_pkt_num:%d ;type:0): receive a create infomatioin\n", rx_pkt_num);
        // 创建 (只有server节点才会收到创建包)
        parsePacket0((char *)packet);
    }
    else if (packet->header.type == 1)
    {
        fprintf_log(log_file, "parsePacket1.\n");
        fprintf_log(log_file, "receive udp(rx_pkt_num:%d ;type:1): as the sponsor, receive a join quest\n", rx_pkt_num);
        // 加入 (只有sponsor节点才会收到加入包)
        parsePacket1((char *)packet);
        // 发送加入广播包
        Packet *packet = createUpdatePacket3();
        usleep(20000);
        broadcast2leaf(packet);
    }
    else if (packet->header.type == 2)
    {
        fprintf_log(log_file, "parsePacket2.\n");
        fprintf_log(log_file, "receive udp(rx_pkt_num:%d ;type:2): as the sponsor, receive a leave quest;\n", rx_pkt_num);
        int leave_node_id = parsePacket2((char *)packet);
        fprintf_log(log_file, "rleave_node_id:%d\n", leave_node_id);

        // 离开 (只有sponsor节点才会收到离开包)
        // 发送离开广播包
        Packet *packet = createUpdatePacket4(leave_node_id);
        broadcast2leaf(packet);
    }
    else if (packet->header.type == 3)
    {
        fprintf_log(log_file, "parsePacket3.\n");
        fprintf_log(log_file, "receive udp (rx_pkt_num:%d ;type:3): sponsor to all member, a node join the group\n", rx_pkt_num);
        // 收到sponsor节点的加入广播包
        parsePacket3((char *)packet);
        updateGroupKey();
    }
    else if (packet->header.type == 4)
    {
        fprintf_log(log_file, "parsePacket4.\n");
        int *leave_node_id = (int *)((char *)packet + sizeof(DataHeader));
        fprintf_log(log_file, "receive udp (rx_pkt_num:%d ;type:4): sponsor to all member, node %d leave the group\n", rx_pkt_num, *leave_node_id);

        parsePacket4((char *)packet);
        updateGroupKey();
    }
    else if (packet->header.type == 5)
    {
        fprintf_log(log_file, "parsePacket5.\n");
        fprintf_log(log_file, "receive udp (rx_pkt_num:%d ;type:5): sponsor to all member, a node update its BK\n", rx_pkt_num);
        // 收到sponsor节点的更新广播包
        parsePacket5((char *)packet);
        updateGroupKey();
    }
    else if (packet->header.type == 6)
    {
        fprintf_log(log_file, "parsePacket6.\n");
        fprintf_log(log_file, "receive udp (rx_pkt_num:%d ;type:6): receive a query request\n", rx_pkt_num);
        // 收到查询请求
        parsePacket6((char *)packet);
    }
    else
    {
        fprintf_log(log_file, "Error: unknown packet type.\n");
    }
    printfTree();
    write_key();
}

// 处理数据包：出队、调用handlePacket函数

int processPackets(void *arg)
{
    fprintf_log(log_file, "Core %u processPackets\n", rte_lcore_id());

    while (1)
    {
        Packet *packet = dequeue();
        // 处理数据包，判断数据包类型，不同的数据包类型执行不同的操作
        if (packet != NULL)
        {
            handlePacket(packet);
            free(packet);
        }
        // usleep(1000);
    }
}

// 构造一个简单的 IPv6 数据包
struct rte_mbuf *construct_ipv6_udp_packet(Packet *packet, struct sockaddr_in6 src_addr, struct sockaddr_in6 dst_addr)
{
    struct rte_mbuf *mbuf;
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv6_hdr *rte_ipv6_hdr;
    struct rte_udp_hdr *rte_udp_hdr;

    DataHeader *header = (DataHeader *)packet;
    uint16_t payload_len = header->length + sizeof(DataHeader); // 设置 payload 长度
    uint16_t hdr_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr) + sizeof(struct rte_udp_hdr);

    uint16_t pkt_len = hdr_len + payload_len;

    // 分配一个 mbuf
    mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (mbuf == NULL)
    {
        printf("Failed to allocate mbuf\n");
        return NULL;
    }

    // 设置以太网头部信息
    eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    memset(eth_hdr->dst_addr.addr_bytes, 0xFF, ETHER_ADDR_LEN); // 目的MAC地址设置为广播
    memset(eth_hdr->src_addr.addr_bytes, 0x00, ETHER_ADDR_LEN); // 源MAC地址设置为0
    eth_hdr->ether_type = htons(0x86DD);                        // 设置以太网类型为IPv6

    // 设置IPv6头部信息
    rte_ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1); // 偏移以太网头部大小
    memset(rte_ipv6_hdr, 0, sizeof(struct rte_ipv6_hdr));
    rte_ipv6_hdr->vtc_flow = htonl(0x60000000);                                  // 设置版本号、Traffic Class和Flow Label
    rte_ipv6_hdr->payload_len = htons(sizeof(struct rte_udp_hdr) + payload_len); // 设置负载长度
    rte_ipv6_hdr->proto = IPPROTO_UDP;                                           // 设置下一层协议为UDP
    rte_ipv6_hdr->hop_limits = 64;                                               // 设置 Hop Limit

    // 设置源和目的IPv6地址
    memcpy(&rte_ipv6_hdr->src_addr, &src_addr.sin6_addr, sizeof(struct in6_addr));
    memcpy(&rte_ipv6_hdr->dst_addr, &dst_addr.sin6_addr, sizeof(struct in6_addr));

    // 设置UDP头部信息
    rte_udp_hdr = (struct rte_udp_hdr *)(rte_ipv6_hdr + 1);                   // 偏移IPv6头部大小
    rte_udp_hdr->src_port = src_addr.sin6_port;                               // 源端口号
    rte_udp_hdr->dst_port = dst_addr.sin6_port;                               // 目的端口号
    rte_udp_hdr->dgram_len = htons(sizeof(struct rte_udp_hdr) + payload_len); // UDP数据报长度
    rte_udp_hdr->dgram_cksum = 0;                                             // 校验和

    // 填充 payload
    rte_memcpy(rte_pktmbuf_mtod_offset(mbuf, uint8_t *, hdr_len), (uint8_t *)packet, payload_len);

    // 设置数据包长度
    mbuf->data_len = pkt_len;
    mbuf->pkt_len = pkt_len;

    rte_udp_hdr->dgram_cksum = rte_ipv6_udptcp_cksum(rte_ipv6_hdr, rte_udp_hdr);
    return mbuf;
}

// 构造一个ipv6、udp数据包:type 6 ,index / counts , payload(MAX_PAYLOAD_LEN 1000)
struct rte_mbuf *construct_ipv6_udp_packet_6(struct sockaddr_in6 src_addr, struct sockaddr_in6 dst_addr, int index, int counts, char *payload, int payload_len)
{
    struct rte_mbuf *mbuf;
    Packet *packet = (Packet *)malloc(sizeof(Packet));
    memset(packet, 0, sizeof(Packet));
    packet->header.type = 6;
    int offset = 0;
    memcpy(packet->data, &index, 4);
    offset += 4;
    memcpy(packet->data + offset, &counts, 4);
    offset += 4;
    memcpy(packet->data + offset, payload, payload_len);
    offset += payload_len;
    packet->header.length = offset;

    mbuf = construct_ipv6_udp_packet(packet, src_addr, dst_addr);
    return mbuf;
}
void write_packet_to_file(struct rte_mbuf *packet)
{
    uint16_t packet_len = rte_pktmbuf_data_len(packet);         // 获取报文长度
    uint8_t *packet_data = rte_pktmbuf_mtod(packet, uint8_t *); // 获取报文数据指针
    // fprintf_log(log_file,"\n");
    // 遍历报文数据，将每个字节的十六进制值打印到文件中

    uint32_t i;
    for (i = 0; i < packet_len; ++i)
    {
        // 打印每个字节的十六进制值
        fprintf(log_file, "%02X ", packet_data[i]);

        // 每行输出 16 个字节
        if ((i + 1) % 16 == 0)
            fprintf(log_file, "\n");
    }
    if (packet_len % 16 != 0)
        fprintf(log_file, "\n");
}
// 发送数据包
int send_packet(struct rte_mbuf *packet)
{
    int ret;
    // 获取端口的数量
    uint16_t nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0)
    {
        rte_exit(EXIT_FAILURE, "No Ethernet ports available\n");
    }
    // 检查端口 ID 是否有效
    if (PORT_ID >= nb_ports)
    {
        rte_exit(EXIT_FAILURE, "Invalid port ID\n");
    }
    // 发送数据包
    /** 配置server mac */
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv6_hdr *ipv6_hdr;
    eth_hdr = rte_pktmbuf_mtod(packet, struct rte_ether_hdr *);
    ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);
    struct in6_addr tmp_srv_addr;
    inet_pton(AF_INET6, SERVER_IP6, &tmp_srv_addr);
    struct in6_addr tmp_dst_addr_0;
    inet_pton(AF_INET6, IP_ADDRESS_NODE0, &tmp_dst_addr_0);
    struct in6_addr tmp_dst_addr_1;
    inet_pton(AF_INET6, IP_ADDRESS_NODE1, &tmp_dst_addr_1);
    memcpy(eth_hdr->src_addr.addr_bytes, MAC_ADDRESS_STR, ETHER_ADDR_LEN);
    // 如果目的ip匹配上，目的mac随之改变
    if (memcmp(ipv6_hdr->dst_addr, &tmp_srv_addr, 16) == 0)
    {
        memcpy(eth_hdr->dst_addr.addr_bytes, SERVER_MAC, ETHER_ADDR_LEN);
        fprintf_log(log_file, "packet type server.\n");
    }
    else if (memcmp(ipv6_hdr->dst_addr, &tmp_dst_addr_0, 16) == 0)
    {
        memcpy(eth_hdr->dst_addr.addr_bytes, MAC_ADDRESS_NODE0, ETHER_ADDR_LEN);
    }
    else if (memcmp(ipv6_hdr->dst_addr, &tmp_dst_addr_1, 16) == 0)
    {
        memcpy(eth_hdr->dst_addr.addr_bytes, MAC_ADDRESS_NODE1, ETHER_ADDR_LEN);
    }
    else
    {
        fprintf_log(log_file, "Error: unknown packet type.\n");
    }

    struct rte_mbuf *cp_pkts[1];
    cp_pkts[0] = rte_pcapng_copy(PORT_ID, 0, packet, packet->pool, UINT32_MAX, time(NULL), RTE_PCAPNG_DIRECTION_UNKNOWN);
    ret = rte_pcapng_write_packets(pcapng, cp_pkts, 1);
    if (ret == -1)
    {
        fprintf_log(log_file, "Error writing packets to pcapng file: %s\n", rte_strerror(rte_errno));
    }
    ret = rte_eth_tx_burst(PORT_ID, 0, &packet, 1);
    if (ret < 1)
    {
        fprintf_log(log_file, "Failed to send packet\n");
    }
    rte_pktmbuf_free(packet);
    fprintf_log(log_file, "send %d packet successfully\n", ret);

    return ret;
}

// 服务器响应请求节点，
// 查询请求函数
void query2server()
{
    char *buffer = malloc(BUFSIZE);
    memset(buffer, 0, BUFSIZE);

    Packet *packet = createQueryPacket6();
    send2server(packet);
    fprintf_log(log_file, "query to server\n");

    // 接收数据包 个数
    struct rte_mbuf *bufs[BURST_SIZE];
    int rx_pkt_num = 0;
    int index = 0;
    int counts = 1000;
    int recv_number = 0;
    int length = 0;

    while (1)
    {
        int nb_rx = rte_eth_rx_burst(PORT_ID, 0, bufs, BURST_SIZE);
        if (nb_rx == 0)
        {
            continue;
        }
        fprintf_log(log_file, "rte_eth_rx_burst recv %d pkt\n", nb_rx);
        rx_pkt_num += nb_rx;
        // 解析数据包
        int i;
        for (i = 0; i < nb_rx; i++)
        {
            struct rte_mbuf *pkt = bufs[i];
            struct rte_mbuf *cp_pkts[1];
            cp_pkts[0] = rte_pcapng_copy(PORT_ID, 0, pkt, pkt->pool, UINT32_MAX, time(NULL), RTE_PCAPNG_DIRECTION_UNKNOWN);
            int ret = rte_pcapng_write_packets(pcapng, cp_pkts, 1);
            if (ret == -1)
            {
                fprintf_log(log_file, "Error writing packets to pcapng file: %s\n", rte_strerror(rte_errno));
            }

            char *payload = rte_pktmbuf_mtod_offset(pkt, char *, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr) + sizeof(struct rte_udp_hdr));
            Packet *packet = (Packet *)payload;
            DataHeader *header = (DataHeader *)packet;
            fprintf_log(log_file, "header->type: %d\n",header->type);
            if (header->type == 6)
            {
                memcpy(&index, packet->data, 4);
                memcpy(&counts, packet->data + 4, 4);
                recv_number++;
                length = header->length - 8;
                memcpy(buffer + index * MAX_PAYLOAD_LEN, packet->data + 8, length);
                fprintf_log(log_file, "udp:response from server, index:%d, counts:%d, length:%d\n", index, counts, length);
                if (recv_number == counts)
                {
                    break;
                }
            }
            else
            {
                fprintf_log(log_file, "Error: unknown packet type.\n");
            }
        }
        for (i = 0; i < nb_rx; i++)
        {
            rte_pktmbuf_free(bufs[i]);
        }
        if (recv_number == counts)
        {
            break;
        }
    }
    // 解析buffer
    parseKeyTree(buffer);
    free(buffer);

}

// 向对应ID的节点发送udp报文 （仅发送） // TODO：ip6、rte_eth_tx_burst()
void send2node(Packet *packet, int nodeID)
{
    struct rte_mbuf *pkt;
    struct sockaddr_in6 src_addr = key_self->addr;
    struct sockaddr_in6 dst_addr = kt_ctx->nodes[nodeID].addr;

    pkt = construct_ipv6_udp_packet(packet, src_addr, dst_addr);

    send_packet(pkt);
    fprintf_log(log_file, "udp:%d send to %d, type: %u, port: %d , tx_pkt_num:%d\n", key_self->id, nodeID, packet->header.type, ntohs(kt_ctx->nodes[nodeID].addr.sin6_port), tx_pkt_num);
    tx_pkt_num++;
}

// 向服务器节点发送udp报文 （仅发送）
void send2server(Packet *packet)
{
    struct rte_mbuf *pkt;
    struct sockaddr_in6 src_addr = key_self->addr;

    struct sockaddr_in6 srv_addr;
    memset(&srv_addr, 0, sizeof(struct sockaddr_in6));
    srv_addr.sin6_family = AF_INET6;
    srv_addr.sin6_port = htons(SERVER_PORT);
    inet_pton(AF_INET6, SERVER_IP6, &(srv_addr.sin6_addr));

    pkt = construct_ipv6_udp_packet(packet, src_addr, srv_addr);
    send_packet(pkt);

    fprintf_log(log_file, "udp:%d send to server, type: %u, tx_pkt_num:%d\n", key_self->id, packet->header.type, tx_pkt_num);
    tx_pkt_num++;
}

// 向所有叶子节点发送广播报文 （仅发送）
void broadcast2leaf(Packet *packet)
{
    int i;
    for (i = 0; i < NODE_NUM; i++)
    {
        if (kt_ctx->nodes[i].flag == 2 && key_self->id != i)
        {
            send2node(packet, i);
        }
    }
    send2server(packet);
}
