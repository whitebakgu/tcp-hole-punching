#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <linux/if_ether.h>

#include "../include/HolePunching.h"

typedef struct {
    int sd;
    int sdStun;
    struct sockaddr_in src_saddr;
    struct sockaddr_in dst_saddr;
} con_info_t;

int gbRun = 1;

int gConnSd;
int gbHandshake;

void* MonitorThread(void* arg)
{
    con_info_t* conInfo = arg;
    int sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    stun_cmd_t stun;
    char buf[65536];
    int len;
    int bFirst = 1;

    if(sd == -1) {
	printf("[%s:%d] socket error: %s\n", __func__, __LINE__, strerror(errno));
	return NULL;
    }

    while(gbRun) {
	fd_set fds;
	struct timeval tv;
	int ret;

	memset(stun.packet, 0, 128);

	FD_ZERO(&fds);
	FD_SET(sd, &fds);

	tv.tv_sec = 0;
	tv.tv_usec = 10000;

	ret = select(sd + 1, &fds, NULL, NULL, &tv);

	if(ret == -1) {
	    printf("[%s:%d] select error: %s\n", __func__, __LINE__, strerror(errno));
	} else if(ret) {
	    if((len = recv(sd, buf, 65536, 0)) < 0) {
		printf("[%s:%d] recv error: %s\n", __func__, __LINE__, strerror(errno));
	    } else {
		struct iphdr* iph = (struct iphdr*)(buf + sizeof(struct ethhdr));
		if(iph->protocol == IPPROTO_TCP) {
		    struct tcphdr* tcph = buf + sizeof(struct ethhdr) + sizeof(struct iphdr);
		    if((tcph->source == conInfo->src_saddr.sin_port && tcph->dest == conInfo->dst_saddr.sin_port) ||
			    (tcph->source == conInfo->dst_saddr.sin_port && tcph->dest == conInfo->src_saddr.sin_port)) {
			if(bFirst && tcph->syn && !tcph->ack) {
			    bFirst = 0;
			    stun.cmd = STUN_CMD_SYN;
			    stun.serial = 12345;
			    stun.bServer = 0;
			    memcpy(stun.packet, buf, len);
			    stun.packetLen = len;

			    if(send(conInfo->sdStun, &stun, sizeof(stun), 0) == -1) {
				printf("[%s:%d] send error: %s\n", __func__, __LINE__, strerror(errno));
			    }
#if 0
			    stun.cmd = STUN_CMD_PACKET_INFO;
			    if(send(conInfo->sdStun, &stun, sizeof(stun), 0) == -1) {
				printf("[%s:%d] send error: %s\n", __func__, __LINE__, strerror(errno));
			    }
#else
			    break;
#endif
			} else {
#if 0
			    stun.cmd = STUN_CMD_PACKET_INFO;
			    stun.serial = 12345;
			    stun.bServer = 0;
			    memcpy(stun.packet, buf, 128);
			    stun.packetLen = len;

			    if(send(conInfo->sdStun, &stun, sizeof(stun), 0) == -1) {
				printf("[%s:%d] send error: %s\n", __func__, __LINE__, strerror(errno));
			    }
#endif
			}
		    }
		}
	    }
	}
    }

    close(sd);

    return NULL;
}

int CreatePeer()
{
    int sdPeer;
    stun_cmd_t stun;
    struct sockaddr_in saddr, caddr;
    socklen_t addrlen = sizeof(struct sockaddr_in);
    int flag = 1;
    int i;
    struct linger lng;

    lng.l_onoff = 1;
    lng.l_linger = 0;

    stun.cmd = STUN_CMD_PORT_PREDICTION;
    stun.serial = 12345;
    stun.bServer = 0;

    bzero(&caddr, sizeof(caddr));
    bzero(&saddr, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = inet_addr("192.168.1.101");
    saddr.sin_port = htons(55555);

    for(i = 0; i < 3; i++) {
	sdPeer = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

	if(sdPeer == -1) {
	    printf("[%s:%d] socket error: %s\n", __func__, __LINE__, strerror(errno));
	    goto CreatePeer_exit;
	}

	if(setsockopt(sdPeer, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) == -1) {
	    printf("[%s:%d] setsockopt error: %s\n", __func__, __LINE__, strerror(errno));
	    goto CreatePeer_exit;
	}

	if(setsockopt(sdPeer, SOL_SOCKET, SO_LINGER, (char *)&lng, sizeof(lng)) == -1) {
	    printf("[%s:%d] setsockopt error: %s\n", __func__, __LINE__, strerror(errno));
	    goto CreatePeer_exit;
	}

	if(caddr.sin_port) {
	    printf("Bind: %s:%d\n", inet_ntoa(caddr.sin_addr.s_addr), ntohs(caddr.sin_port));
	    if(bind(sdPeer, (struct sockaddr*)&caddr, sizeof(caddr)) == -1) {
		printf("[%s:%d] bind error: %s\n", __func__, __LINE__, strerror(errno));
		goto CreatePeer_exit;
	    }
	}

	if(connect(sdPeer, (struct sockaddr*)&saddr, sizeof(saddr)) == -1) {
	    printf("[%s:%d] connect error: %s\n", __func__, __LINE__, strerror(errno));
	    goto CreatePeer_exit;
	}

	if(send(sdPeer, &stun, sizeof(stun), 0) == -1) {
	    printf("[%s:%d] send error: %s\n", __func__, __LINE__, strerror(errno));
	    goto CreatePeer_exit;
	}

	if(!caddr.sin_port) {
	    if(getsockname(sdPeer, (struct sockaddr*)&caddr, &addrlen) == -1) {
		printf("[%s:%d] getsockname error: %s\n", __func__, __LINE__, strerror(errno));
		goto CreatePeer_exit;
	    }
	}

	if(i < 2) {
	    close(sdPeer);
	}
    }

    return sdPeer;

CreatePeer_exit:
    if(sdPeer != -1) {
	close(sdPeer);
    }

    return -1;
}

void* ConnectThread(void* arg)
{
    con_info_t* conInfo = arg;
    pthread_t synThr;
    char* pAddr;
    unsigned short port;
    pthread_t monThr;
    int bFirst = 1;
    stun_cmd_t stun;

    pAddr = inet_ntoa(conInfo->dst_saddr.sin_addr);
    port = ntohs(conInfo->dst_saddr.sin_port);

    bzero(&conInfo->dst_saddr, sizeof(conInfo->dst_saddr));
    conInfo->dst_saddr.sin_family = AF_INET;
    conInfo->dst_saddr.sin_addr.s_addr = inet_addr(pAddr);
    conInfo->dst_saddr.sin_port = htons(port);

    if(pthread_create(&monThr, NULL, MonitorThread, conInfo)) {
	printf("[%s:%d] pthread_create error\n", __func__, __LINE__);
	goto ConnectThread_exit;
    }

    if(connect(conInfo->sd, (struct sockaddr*)&conInfo->dst_saddr, sizeof(conInfo->dst_saddr)) == -1) {
	printf("[%s:%d] connect error: %s\n", __func__, __LINE__, strerror(errno));
	goto ConnectThread_exit;
    }

    stun.cmd = STUN_CMD_HANDSHAKE_OK;
    stun.serial = 12345;
    stun.bServer = 0;

    if(send(conInfo->sdStun, &stun, sizeof(stun), 0) == -1) {
	printf("[%s:%d] send error: %s\n", __func__, __LINE__, strerror(errno));
    }

    while(!gbHandshake) {
	sleep(1);
    }

    if(send(conInfo->sd, "Client OK", 10, 0) == -1) {
	printf("[%s:%d] send error: %s\n", __func__, __LINE__, strerror(errno));
	goto ConnectThread_exit;
    }

    fcntl(conInfo->sd, F_SETFL, fcntl(conInfo->sd, F_GETFL, 0) | O_NONBLOCK);

    while(gbRun) {
	fd_set fds;
	struct timeval tv;
	int ret;
	struct linger lng;

	FD_ZERO(&fds);
	FD_SET(conInfo->sd, &fds);

	tv.tv_sec = 0;
	tv.tv_usec = 10000;

	ret = select(conInfo->sd + 1, &fds, NULL, NULL, &tv);

	if(ret == -1) {
	    printf("[%s:%d] select error: %s\n", __func__, __LINE__, strerror(errno));
	    goto ConnectThread_exit;
	} else if(ret) {
	    char buf[128];

	    if(recv(conInfo->sd, buf, 128, 0) == -1) {
		printf("[%s:%d] recv error: %s\n", __func__, __LINE__, strerror(errno));
		goto ConnectThread_exit;
	    }

	    printf("%s\n", buf);
	    if(bFirst) {
		bFirst = 0;
		gConnSd = conInfo->sd;

		stun.cmd = STUN_CMD_CONNECT_OK;
		stun.serial = 12345;
		stun.bServer = 0;

		if(send(conInfo->sdStun, &stun, sizeof(stun), 0) == -1) {
		    printf("[%s:%d] send error: %s\n", __func__, __LINE__, strerror(errno));
		}
	    }
	}
    }

ConnectThread_exit:
    free(conInfo);
    return NULL;
}

void HolepRun(char* address, unsigned short port, int serial)
{
    int sdStun = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), sdPeer = -1;
    struct sockaddr_in saddr;
    int flag;
    stun_cmd_t stun;
    int addrLen;

    if(sdStun == -1) {
	printf("[%s:%d] socket error: %s\n", __func__, __LINE__, strerror(errno));
	return;
    }

    flag = 1;
    if(setsockopt(sdStun, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) == -1) {
	printf("[%s:%d] setsockopt error: %s\n", __func__, __LINE__, strerror(errno));
	goto exit;
    }

    bzero(&saddr, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = inet_addr(address);
    saddr.sin_port = htons(port);

    if(connect(sdStun, (struct sockaddr*)&saddr, sizeof(saddr)) == -1) {
	printf("[%s:%d] connect error: %s\n", __func__, __LINE__, strerror(errno));
	goto exit;
    }

    stun.cmd = STUN_CMD_REQ_INFO;
    stun.serial = serial;
    stun.bServer = 0;

    if(send(sdStun, &stun, sizeof(stun), 0) == -1) {
	printf("[%s:%d] send error: %s\n", __func__, __LINE__, strerror(errno));
	goto exit;
    }

    fcntl(sdStun, F_SETFL, fcntl(sdStun, F_GETFL, 0) | O_NONBLOCK);

    while(gbRun) {
	fd_set fds;
	struct timeval tv;
	int ret;
	struct linger lng;

	lng.l_onoff = 1;
	lng.l_linger = 0;

	FD_ZERO(&fds);
	FD_SET(sdStun, &fds);

	tv.tv_sec = 0;
	tv.tv_usec = 10000;

	ret = select(sdStun + 1, &fds, NULL, NULL, &tv);

	if(ret == -1) {
	    printf("[%s:%d] select error: %s\n", __func__, __LINE__, strerror(errno));
	    goto exit;
	} else if(ret) {
	    pthread_t conThr;
	    con_info_t* conInfo;

	    if(recv(sdStun, &stun, sizeof(stun), 0) <= 0) {
		printf("[%s:%d] recv error: %s\n", __func__, __LINE__, strerror(errno));
		goto exit;
	    }

	    switch(stun.cmd) {
		case STUN_CMD_REQ_INFO:
		    sdPeer = CreatePeer();
		    if(sdPeer == -1) {
			printf("[%s:%d] CreatePeer error\n", __func__, __LINE__);
			goto exit;
		    }
		    break;

		case STUN_CMD_RESP_INFO:
		    addrLen = sizeof(saddr);
		    if(getsockname(sdPeer, (struct sockaddr*)&saddr, &addrLen) == -1) {
			printf("[%s:%d] getsockname error: %s\n", __func__, __LINE__, strerror(errno));
			goto exit;
		    }

		    close(sdPeer);
		    sdPeer = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

		    if(sdPeer == -1) {
			printf("[%s:%d] socket error: %s\n", __func__, __LINE__, strerror(errno));
			goto exit;
		    }

		    if(setsockopt(sdPeer, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) == -1) {
			printf("[%s:%d] setsockopt error: %s\n", __func__, __LINE__, strerror(errno));
			goto exit;
		    }

		    if(setsockopt(sdPeer, SOL_SOCKET, SO_LINGER, (char *)&lng, sizeof(lng)) == -1) {
			printf("[%s:%d] setsockopt error: %s\n", __func__, __LINE__, strerror(errno));
			goto exit;
		    }

		    if(bind(sdPeer, (struct sockaddr*)&saddr, sizeof(saddr)) == -1) {
			printf("[%s:%d] bind error: %s\n", __func__, __LINE__, strerror(errno));
			goto exit;
		    }

		    conInfo = malloc(sizeof(*conInfo));
		    if(!conInfo) {
			printf("[%s:%d] malloc error: %s\n", __func__, __LINE__, strerror(errno));
			goto exit;
		    }

		    conInfo->sd = sdPeer;
		    conInfo->src_saddr = saddr;
		    conInfo->dst_saddr = stun.saddr;
		    conInfo->sdStun = sdStun;

		    if(pthread_create(&conThr, NULL, ConnectThread, conInfo)) {
			printf("[%s:%d] pthread_create error\n", __func__, __LINE__);
			free(conInfo);
			goto exit;
		    }
		    break;

		case STUN_CMD_HANDSHAKE_OK:
		    gbHandshake = 1;
		    break;

		case STUN_CMD_CONNECT_OK:
		    send(gConnSd, "Client Real OK", 15, 0);
		    break;
		default:
		    printf("[%s:%d] unknown stun command\n", __func__, __LINE__);
		    break;
	    }
	}
    }

exit:
    if(sdStun != -1) {
	close(sdStun);
    }

    if(sdPeer != -1) {
	close(sdPeer);
    }
}

void PrintHelp(char* argv[])
{
    printf("Usage: %s -a {ip address} -p {port number} -s {serial number}\n"
	    "  -a addr   : Stun server address\n"
	    "  -p port   : Stun server port\n"
	    "  -s serial : Hole server hexa  serial number\n"
	    "  -h        : Print this usage\n", argv[0]);
}

void SigHandler(int signum)
{
    switch(signum) {
	case SIGTERM:
	case SIGINT:
	    gbRun = 0;
	    break;
	default:
	    break;
    }
}

int main(int argc, char* argv[])
{
    int opt;
    char* address = NULL;
    unsigned short port = 0;
    int serial = 0;
    struct sigaction sigaInst;

    while((opt = getopt(argc, argv, "ha:p:s:")) != -1) {
	switch(opt) {
	    case 'a':
		address = optarg;
		break;

	    case 'p':
		port = atoi(optarg);
		break;

	    case 's':
		serial = strtol(optarg, NULL, 16);
		break;

	    case 'h':
	    default:
		PrintHelp(argv);
		return -1;
	}
    }

    if(!address) {
	PrintHelp(argv);
	return -1;
    }

    if(!port) {
	PrintHelp(argv);
	return -1;
    }

    if(!serial) {
	PrintHelp(argv);
	return -1;
    }

    signal(SIGPIPE, SIG_IGN);

    sigaInst.sa_flags = 0;
    sigemptyset(&sigaInst.sa_mask);
    sigaddset(&sigaInst.sa_mask, SIGTERM);
    sigaddset(&sigaInst.sa_mask, SIGINT);

    sigaInst.sa_handler = SigHandler;
    sigaction(SIGTERM, &sigaInst, NULL);
    sigaction(SIGINT, &sigaInst, NULL);

    printf("Start HolepRun\n");
    HolepRun(address, port, serial);
    printf("End HolepRun\n");

    return 0;
}
