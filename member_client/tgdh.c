#include "tgdh.h"

int processDaemon(void *arg)
{
    rte_spinlock_init(&lock);

    fprintf_log(log_file, "Core %u processDaemon\n", rte_lcore_id());

    // 创建接收队列
    queue = initQueue();

    // 创建数据包处理线程：出队、判断数据包类型、不同的数据包类型执行不同的操作
    rte_eal_remote_launch(processPackets, NULL, rte_lcore_id() + 1);

    // Main loop to receive packets
    Packet *packet = (Packet *)malloc(sizeof(Packet));
    struct rte_mbuf *bufs[BURST_SIZE];
    uint16_t port_id = PORT_ID;
    while (1)
    {
        // TODO rte_eth_rx_burst()、rte_eth_tx_burst()的网口号没有设置
        uint16_t nb_rx = rte_eth_rx_burst(PORT_ID, 0, bufs, BURST_SIZE);
        if (nb_rx > 0) {
            int i;
            for (i = 0; i < nb_rx; i++)
            {
                struct rte_mbuf *pkt = bufs[i];
                
                struct rte_mbuf *cp_pkts[1];
                cp_pkts[0] = rte_pcapng_copy(PORT_ID, 0, pkt, pkt->pool, UINT32_MAX, time(NULL), RTE_PCAPNG_DIRECTION_UNKNOWN);
                int ret;
                ret = rte_pcapng_write_packets(pcapng, cp_pkts, 1);
                if (ret == -1)
                {
                    fprintf_log(log_file, "Error writing packets to pcapng file: %s\n", rte_strerror(rte_errno));
                }
                // 解析数据包头部
                struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
                struct rte_ipv6_hdr *rte_ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1); // 偏移以太网头部大小
                struct rte_udp_hdr *rte_udp_hdr = (struct rte_udp_hdr *)(rte_ipv6_hdr + 1);   // 偏移IPv6头部大小

                // 检查是否为 IPv6 数据包
                if (ntohs(eth_hdr->ether_type) != 0x86DD)
                {
                    // rte_eth_tx_burst(port_id, 0, &pkt, 1);
                    rte_pktmbuf_free(pkt);
                    fprintf_log(log_file, "Forwarded non-IPv6 packet, eth_hdr->ether_type:%x\n",eth_hdr->ether_type);
                    continue;
                }
                // 检查目的地址是否等于本机地址
                if (memcmp(&(rte_ipv6_hdr->dst_addr), &(key_self->addr.sin6_addr), sizeof(struct in6_addr)) != 0)
                {
                    // rte_eth_tx_burst(port_id, 0, &pkt, 1);
                    rte_pktmbuf_free(pkt);
                    fprintf_log(log_file, "Forwarded packet with incorrect destination address\n");
                    continue;
                }
                // 检查是否为 UDP 数据包
                if (rte_ipv6_hdr->proto != IPPROTO_UDP)
                {
                    // rte_eth_tx_burst(port_id, 0, &pkt, 1); // 转发数据包
                    rte_pktmbuf_free(pkt);
                    fprintf_log(log_file, "Received non-UDP packet\n");
                    continue;
                }
                // 检查目的端口是否正确
                if (ntohs(rte_udp_hdr->dst_port) != TGDH_PORT)
                {
                    // rte_eth_tx_burst(port_id, 0, &pkt, 1); // 转发数据包
                    rte_pktmbuf_free(pkt);
                    // 目的端口不正确，记录日志并转发
                    fprintf_log(log_file, "Destination port does not match, ntohs(rte_udp_hdr->dst_port): %d \n",ntohs(rte_udp_hdr->dst_port));
                    continue;
                }
                packet = (Packet *)(rte_udp_hdr + 1);

                enqueue(packet);                
                rte_pktmbuf_free(pkt);
                rx_pkt_num++;
                memset(packet, 0, sizeof(Packet));
                fprintf(log_file, "\n");
                fprintf_log(log_file, "Received UDP from port %d to %d\n", ntohs(rte_udp_hdr->src_port), ntohs(rte_udp_hdr->dst_port));
            }
        }
        else {
            continue;
        }
    }
    return 0;
}

// 初始化
void initTGDH()
{
    // 创建上下文变量
    kt_ctx = (keytree_context *)malloc(sizeof(keytree_context));
    memset(kt_ctx, 0, sizeof(keytree_context));
    strcpy(kt_ctx->group_name, TGDH_GROUP_NAME);
    kt_ctx->alpha = BN_new();
    kt_ctx->p = BN_new();
    int i;
    for (i = 0; i < NODE_NUM; i++)
    {
        kt_ctx->nodes[i].id = i;
    }

    key_self = (keytree_self *)malloc(sizeof(keytree_self));
    memset(key_self, 0, sizeof(keytree_self));
    // 随机生成自己的密钥
    key_self->self_key = BN_new();
    BN_rand(key_self->self_key, KEY_LEN * 8, 0, 0);
    // 地址addr
    key_self->addr.sin6_family = AF_INET6;
    key_self->addr.sin6_port = htons(TGDH_PORT);
    inet_pton(AF_INET6, IP_ADDRESS_STR, &(key_self->addr.sin6_addr));
}

// 创建group，初始化密钥树，自己作为根节点，向服务器节点发送创建信息
// dataheader(type 0) + groupname + rounds + alpha + p + root_nodes
int createGroup()
{
    // 初始化树信息
    // 随机生成群组参数
    // BN_rand(kt_ctx->alpha, KEY_LEN * 8, 0, 0);
    BN_set_word(kt_ctx->alpha, 2); // 选择一个常见的底数，也可以是其他值
    BN_generate_prime_ex(kt_ctx->p, KEY_LEN * 8, 0, NULL, NULL, NULL);
    kt_ctx->rounds = 0;
    kt_ctx->nodes[0].flag = 2;
    kt_ctx->nodes[0].addr = key_self->addr;
    kt_ctx->nodes[0].blind_key = generateBlindKey(key_self->self_key, kt_ctx->alpha, kt_ctx->p);
    
    Packet *packet = createCreatePacket0();
    
    // 发送数据包
    send2server(packet);

    kt_ctx->rounds++;
    // 释放资源
    free(packet);
    // 开启线程监听其他节点的回复
    printfTree();
    write_key();
    rte_eal_remote_launch(processDaemon, NULL, rte_lcore_id() + 1);
}

// 查询密钥树，向服务器节点发送查询请求，并将回复的密钥树信息存储在本地
void queryGroup()
{
    query2server();
}

// 节点加入
int joinGroup()
{
    // 向服务器查询密钥树
    queryGroup();
    key_self->id = -1; // 表示群组外成员
    printfTree();

    rte_eal_remote_launch(processDaemon, NULL, rte_lcore_id() + 1);

    fprintf_log(log_file, "join group.\n");
    // 向sponsor节点发送加入请求及自己的blinded key
    Packet *packet = createJoinPacket1();
    fprintf_log(log_file, "findJoinSponsorID: %d\n", findJoinSponsorID());
    send2node(packet, findJoinSponsorID());

    // 修改自己的id
    key_self->id = findRightChildID(findJoinSponsorID());
    free(packet);
}

// 节点离开
int leaveGroup()
{
    fprintf(log_file, "\n\n");
    fprintf_log(log_file, "leave group.\n");
    // 向sponsor节点发送离开请求
    Packet *packet = createLeavePacket2();
    send2node(packet, findLeaveSponsorID(key_self->id));
    // 释放资源
    free(packet);
    free(key_self);
    free(kt_ctx);
}

// 更新密钥树，自己作为sponsor节点广播自己路径上的blinded key
int updateGroup()
{
    fprintf(log_file, "\n\n");
    fprintf_log(log_file, "update group key.\n");
    // 随机生成
    BN_rand(key_self->self_key, KEY_LEN * 8, 0, 0);
    BN_free(kt_ctx->nodes[key_self->id].blind_key);
    kt_ctx->nodes[key_self->id].blind_key = generateBlindKey(key_self->self_key, kt_ctx->alpha, kt_ctx->p);
    // 更新路径上的节点的blind_key
    updateGroupKey();
    // 向所有叶子节点和服务器发送广播报文
    Packet *packet = createUpdatePacket5();
    printfTree();
    write_key();
    broadcast2leaf(packet);
    // 释放资源
    free(packet);
}
