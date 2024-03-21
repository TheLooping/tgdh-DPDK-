#ifndef TGDH_H
#define TGDH_H

#include "pkt_daemon.h"




extern FILE *log_file;
extern int recv_socket;

// 功能：1创建socket 2绑定端口、监听 3创建数据包处理线程 4数据包入队 5关闭socket等
#ifdef _WIN32
DWORD WINAPI processDaemon();
#else
void *processDaemon();
#endif


// 初始化
void initTGDH();




#endif /* TGDH_H */