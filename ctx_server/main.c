#include "tgdh.h"

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;// 只使用于入队和出队操作
PacketQueue *queue;
keytree_context *kt_ctx;
keytree_self *key_self;


int tx_pkt_num = 0;
int rx_pkt_num = 0;
int recv_socket;
FILE *log_file;




int main()
{   
    log_file = fopen(LOG_FILE_NAME, "a");
    fprintf(log_file,"\n\n");
    fprintf(log_file, "============================================================================\n");
    fprintf(log_file, "============================================================================\n");
    fprintf(log_file, "============================================================================\n");


    initTGDH(); //new

    pthread_t thread_id;
    pthread_create(&thread_id, NULL, processDaemon, NULL);
    pthread_join(thread_id, NULL);

    return 0;
}
