#include "tgdh.h"

// 兼容windows和linux的线程函数 processDaemon
#ifdef _WIN32
DWORD WINAPI processDaemon()
#else
void *processDaemon()
#endif
{
    // 初始化winsock
#ifdef _WIN32
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        fprintf_log(log_file,"WSAStartup failed.\n");
        return 2;
    }
#endif

#ifdef _WIN32
    hMutex = CreateMutex(NULL, FALSE, NULL);
#else
    pthread_mutex_init(&mutex, NULL);
#endif

    struct sockaddr_in6 server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    if ((recv_socket = socket(AF_INET6, SOCK_DGRAM, 0)) < 0)
    {
        fprintf_log(log_file,"socket creation failed.\n");
        return NULL;
    }
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin6_family = AF_INET6;
    server_addr.sin6_port = htons(SERVER_PORT);    
    inet_pton(AF_INET6, SERVER_IP6, &(server_addr.sin6_addr));
    // const char *interface_name = INTERFACE_NAME;
    // if (setsockopt(recv_socket, SOL_SOCKET, SO_BINDTODEVICE, interface_name, strlen(interface_name) + 1) < 0) {
    //     fprintf_log(log_file, "setsockopt failed");
    //     perror("setsockopt failed");
    //     exit(EXIT_FAILURE);
    // }
    int ret;
    if ((ret = bind(recv_socket, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_in6))) < 0) {
        perror("bind failed");
        printf("Error code: %d\n", errno);
        exit(EXIT_FAILURE);
    }
    printf("bind ok!\n");

    

    // 创建接收队列
    queue = initQueue();

    // 创建数据包处理线程：出队、判断数据包类型、不同的数据包类型执行不同的操作
#ifdef _WIN32
    HANDLE hThread_packets = CreateThread(NULL, 0, processPackets, NULL, 0, NULL);
#else
    pthread_t tid_packets;
    pthread_create(&tid_packets, NULL, processPackets, NULL);
#endif

    // Main loop to receive packets
    Packet *packet = (Packet *)malloc(sizeof(Packet));
    fprintf_log(log_file, "start recvfrom\n");
    while (1)
    {
        int n = recvfrom(recv_socket, (char *)packet, MAX_MSG_LEN, MSG_WAITALL,
                         (struct sockaddr *)&client_addr, &client_addr_len);
        if (n > 0)
        {
            packet->data[n - sizeof(DataHeader)] = '\0';
            enqueue(packet);
            fprintf(log_file,"\n"); 
            fprintf_log(log_file, "udp: receive type: %u, rx_pkt_num:%d.\n", packet->header.type, rx_pkt_num);
            rx_pkt_num++;
            memset(packet, 0, sizeof(Packet));
        }
    }
#ifdef _WIN32
    CloseHandle(hThread_packets);
    CloseHandle(hMutex);
#else
    pthread_join(tid_packets, NULL);
#endif

#ifdef _WIN32
    WSACleanup();
#endif
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

    for (int i = 0; i < NODE_NUM; i++)
    {
        kt_ctx->nodes[i].id = i;
    }
    //new ,no need selfkey
}

