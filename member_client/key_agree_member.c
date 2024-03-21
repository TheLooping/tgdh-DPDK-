#include "tgdh.h"

#define LOG_FILE_FORMAT "log_%c.txt"

rte_spinlock_t lock;

PacketQueue *queue;
keytree_context *kt_ctx;
keytree_self *key_self;


int tx_pkt_num = 0;
int rx_pkt_num = 0;
FILE *log_file;
struct rte_mempool *mbuf_pool;
struct rte_pcapng *pcapng;

int tgdh_start()
{
    const char *pcapng_filename = "cap.pcapng";
    int pcapng_fd  = open(pcapng_filename, O_CREAT | O_RDWR | O_APPEND,
                     (__S_IREAD | __S_IWRITE) | S_IRGRP | S_IROTH);
    pcapng = rte_pcapng_fdopen(pcapng_fd, NULL, NULL, NULL, NULL);
    char log_filename[20] = {'\0'};
    char *ip_last_byte;
    ip_last_byte = (char *)strrchr(IP_ADDRESS_STR, ':') + 1;
    snprintf(log_filename, sizeof(log_filename), LOG_FILE_FORMAT, *ip_last_byte);
    log_file = fopen(log_filename, "a");
    fprintf(log_file,"\n\n");
    fprintf(log_file, "============================================================================\n");
    fprintf(log_file, "============================================================================\n");
    fprintf(log_file, "============================================================================\n");
    char command[64];
    snprintf(command, sizeof(command), "rm -rf ./%s", ENCRYPTION_KEY_DIR);
    system(command);
    key_dir_init();

    initTGDH();
    int state = 0; // 当前状态 0未加入 1已加入
    // 循环接收命令 create query join leave update exit
    char cmd[32];
    while(1){
        printf("Please input command: ");
        scanf("%s", cmd);
        if(strcmp(cmd, "create") == 0){
            // 第一个节点创建
            if(state == 0){
                // 创建密钥群
                createGroup();
                state = 1;                    
            }
            else{
                fprintf_log(log_file,"You have already created a group.\n");
            }
        }
        else if(strcmp(cmd, "query") == 0){            
            queryGroup();            
        }
        else if(strcmp(cmd, "join") == 0){
            if(state == 0){
                joinGroup();
                state = 1;
            }
            else{
                fprintf_log(log_file,"You have already joined a group.\n");
            }                
        }
        else if(strcmp(cmd, "leave") == 0){
            if(state == 0){
                fprintf_log(log_file,"You have not joined a group yet.\n");
            }
            else{
                leaveGroup();
                state = 0;
            }
            
            goto end;
        }
        else if(strcmp(cmd, "update") == 0){
            if(state == 0){
                fprintf_log(log_file,"You have not joined a group yet.\n");
            }
            else{
                updateGroup();
            }
        }
        else if(strcmp(cmd, "exit") == 0){
            if(state != 0){
                leaveGroup();
                state = 0;
            }
            fprintf_log(log_file,"exit.\n");
            goto end;
        }     
        else{
            printf("Invalid command. Please input create, join, leave or update.\n");
        }
    }

end:
    fprintf_log(log_file, "udp:rx_pkt_num:%d.\n", rx_pkt_num);
    fprintf_log(log_file, "udp:tx_pkt_num:%d.\n", tx_pkt_num);
    fclose(log_file);
    close(pcapng_fd);

    
    printf("udp:rx_pkt_num:%d.\n", rx_pkt_num);
    printf("udp:tx_pkt_num:%d.\n", tx_pkt_num);
    
    return 0;
}

/* Main functional part of port initialization. 8< */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf;
	const uint16_t rx_rings = 1, tx_rings = 1;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	memset(&port_conf, 0, sizeof(struct rte_eth_conf));

	retval = rte_eth_dev_info_get(port, &dev_info);
	if (retval != 0) {
		printf("Error during getting device (port %u) info: %s\n",
				port, strerror(-retval));
		return retval;
	}

	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

	/* Starting Ethernet port. 8< */
	retval = rte_eth_dev_start(port);
	/* >8 End of starting of ethernet port. */
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	struct rte_ether_addr addr;
	retval = rte_eth_macaddr_get(port, &addr);
	if (retval != 0)
		return retval;

	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port, RTE_ETHER_ADDR_BYTES(&addr));

	/* Enable RX in promiscuous mode for the Ethernet device. */
	retval = rte_eth_promiscuous_enable(port);
	/* End of setting RX port in promiscuous mode. */
	if (retval != 0)
		return retval;

	return 0;
}
/* >8 End of main functional part of port initialization. */

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */

 /* Basic forwarding application lcore. 8< */
static __rte_noreturn void
lcore_main(void)
{
	uint16_t port;

	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	RTE_ETH_FOREACH_DEV(port) {
		if (rte_eth_dev_socket_id(port) >= 0 &&
				rte_eth_dev_socket_id(port) !=
						(int)rte_socket_id())
			printf("WARNING, port %u is on remote NUMA node to "
					"polling thread.\n\tPerformance will "
					"not be optimal.\n", port);
    }
	printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n", rte_lcore_id());

	/* Main work of application. 8< */
	tgdh_start();
	/* >8 End of application. */
    exit(EXIT_SUCCESS);
}
/* >8 End Basic forwarding application lcore. */

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{

	unsigned nb_ports;
	uint16_t portid;

	/* Initializion the Environment Abstraction Layer (EAL). 8< */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
	/* >8 End of initialization the Environment Abstraction Layer (EAL). */

	argc -= ret;
	argv += ret;

	/* Check that there is an even number of ports to send/receive on. */
	nb_ports = rte_eth_dev_count_avail();
	printf("\nnb_ports:%d\n", nb_ports);

	/* Creates a new mempool in memory to hold the mbufs. */

	/* Allocates mempool to hold the mbufs. 8< */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	/* >8 End of allocating mempool to hold mbuf. */

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initializing all ports. 8< */
	RTE_ETH_FOREACH_DEV(portid)
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",
					portid);
	/* >8 End of initializing all ports. */

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

	/* Call lcore_main on the main core only. Called on single lcore. 8< */
	lcore_main();
	/* >8 End of called on single lcore. */

	/* clean up the EAL */
	rte_eal_cleanup();

	return 0;
}
