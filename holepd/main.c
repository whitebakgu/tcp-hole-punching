#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if.h>
#include <linux/sockios.h>

#include "../include/HolePunching.h"

typedef struct {
    int sd;
    int sdStun;
    struct sockaddr_in src_saddr;
    struct sockaddr_in dst_saddr;
    char packet[128];
    int packetLen;
} con_info_t;

struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

int gbRun = 1;

int gConnSd;
int gbHandshake;

unsigned short csum(unsigned short *buf, int len)
{
    unsigned long sum;
    for(sum=0; len>0; len-=sizeof(unsigned short))
	sum += *buf++;
    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

void* SynSend(void* arg)
{
    con_info_t* conInfo = arg;
    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    int sd;
    struct iphdr* iph = packet;
    struct tcphdr* tcph = packet + sizeof(struct iphdr);
    struct iphdr* iphPack = conInfo->packet + sizeof(struct ethhdr);
    struct tcphdr* tcphPack = conInfo->packet + sizeof(struct ethhdr) + sizeof(struct iphdr);
    struct pseudo_header psh;
    int one = 1;
    char addr1[32], addr2[32];
    struct sockaddr_in saddr;
    char pseudogram[sizeof(struct pseudo_header) + sizeof(struct tcphdr)];
    int ret;
    int flag = 1;

    sd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if(sd == -1) {
	printf("[%s:%d] socket error: %s\n", __func__, __LINE__, strerror(errno));
	return NULL;
    }

    memset(packet, 0, sizeof(packet));

    iph->ihl = sizeof(*iph) / 4;
    iph->version = 4;
    iph->tot_len = htons(sizeof(packet));
    iph->id = iphPack->id;
    iph->frag_off = 0x40;
    iph->ttl = iphPack->ttl;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = conInfo->src_saddr.sin_addr.s_addr;
    iph->daddr = conInfo->dst_saddr.sin_addr.s_addr;

    tcph->source = conInfo->src_saddr.sin_port;
    tcph->dest = conInfo->dst_saddr.sin_port;
    memcpy(&tcph->seq, &tcphPack->seq, sizeof(tcph->seq));
    tcph->doff = 5;
    tcph->syn = tcphPack->syn;
    tcph->ack = tcphPack->ack;
    tcph->window = htons(14480);

    psh.source_address = iph->saddr;
    psh.dest_address = iph->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(pseudogram) - sizeof(psh));

    memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcph, ntohs(psh.tcp_length));

    tcph->check = csum((unsigned short*)pseudogram, sizeof(pseudogram));

    strcpy(addr1, inet_ntoa(iph->saddr));
    strcpy(addr2, inet_ntoa(iph->daddr));

    if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) == -1) {
	printf("[%s:%d] setsockopt error: %s\n", __func__, __LINE__, strerror(errno));
	goto SynSend_exit;
    }

    conInfo->dst_saddr.sin_family = AF_INET;
    if((ret = sendto(sd, packet, sizeof(packet), 0, (struct sockaddr*)&conInfo->dst_saddr, sizeof(saddr))) == -1) {
	printf("[%s:%d] sendto error: %s\n", __func__, __LINE__, strerror(errno));
	goto SynSend_exit;
    }

SynSend_exit:
    close(sd);
}

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
			if(bFirst && tcph->syn && tcph->ack) {
			    bFirst = 0;
			    stun.cmd = STUN_CMD_SYN_ACK;
			    stun.serial = 12345;
			    stun.bServer = 1;
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
			    stun.bServer = 1;
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

void* ConnectThread(void* arg)
{
    con_info_t* conInfo = arg;
    pthread_t synThr;
    char testBuf[10] = {0,};
    int sdPeer;
    struct sockaddr_in peerAddr;
    socklen_t addrLen = sizeof(peerAddr);
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

    if(listen(conInfo->sd, 5) == -1) {
	printf("[%s:%d] listen error: %s\n", __func__, __LINE__, strerror(errno));
	goto ConnectThread_exit;
    }

    sdPeer = accept(conInfo->sd, (struct sockaddr*)&peerAddr, &addrLen);
    if(sdPeer == -1) {
	printf("[%s:%d] accept error: %s\n", __func__, __LINE__, strerror(errno));
	goto ConnectThread_exit;
    }

    conInfo->sd = sdPeer;

    stun.cmd = STUN_CMD_HANDSHAKE_OK;
    stun.serial = 12345;
    stun.bServer = 1;

    if(send(conInfo->sdStun, &stun, sizeof(stun), 0) == -1) {
	printf("[%s:%d] send error: %s\n", __func__, __LINE__, strerror(errno));
    }

    while(!gbHandshake) {
	sleep(1);
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
		stun.bServer = 1;

		if(send(conInfo->sdStun, &stun, sizeof(stun), 0) == -1) {
		    printf("[%s:%d] send error: %s\n", __func__, __LINE__, strerror(errno));
		}

		if(send(conInfo->sd, "Server OK", 10, 0) == -1) {
		    printf("[%s:%d] send error: %s\n", __func__, __LINE__, strerror(errno));
		    goto ConnectThread_exit;
		}
	    }
	}
    }

ConnectThread_exit:
    free(conInfo);
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
    stun.bServer = 1;

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

	    stun.saddr = caddr;
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

void HolepDaemonRun(char* address, unsigned short port, int serial)
{
    int sdStun = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    int sdPeer = -1;
    struct sockaddr_in saddr;
    stun_cmd_t stun;
    socklen_t addrLen;
    int flag = 1;
    socklen_t ttl;
    int i;

    if(sdStun == -1) {
	printf("[%s:%d] socket error: %s\n", __func__, __LINE__, strerror(errno));
	return;
    }

    if(setsockopt(sdStun, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) == -1) {
	printf("[%s:%d] setsockopt error: %s\n", __func__, __LINE__, strerror(errno));
	goto exit;
    }

    bzero(&saddr, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = inet_addr(address);
    saddr.sin_port = htons(port);

    for(i = 1; i <= 64; i++) {
	ttl = i;
	if(setsockopt(sdStun, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) == -1) {
	    printf("[%s:%d] setsockopt error: %s\n", __func__, __LINE__, strerror(errno));
	    goto exit;
	}

	if(connect(sdStun, (struct sockaddr*)&saddr, sizeof(saddr)) != -1) {
	    break;
	}
    }

    if(i > 64) {
	printf("[%s:%d] connect error: %s\n", __func__, __LINE__, strerror(errno));
	goto exit;
    }

    stun.cmd = STUN_CMD_REGISTER;
    stun.serial = serial;
    stun.bServer = 1;

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
	static con_info_t* synConInfo;

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

		    {
			unsigned int tmpAddr = saddr.sin_addr.s_addr;
			saddr.sin_addr.s_addr = htonl(INADDR_ANY);

			if(bind(sdPeer, (struct sockaddr*)&saddr, sizeof(saddr)) == -1) {
			    printf("[%s:%d] bind error: %s\n", __func__, __LINE__, strerror(errno));
			    goto exit;
			}

			saddr.sin_addr.s_addr = tmpAddr;
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

		    synConInfo = malloc(sizeof(*synConInfo));
		    bzero(synConInfo, sizeof(synConInfo));
		    synConInfo->src_saddr = stun.saddr;
		    synConInfo->dst_saddr = saddr;

		    if(send(sdStun, &stun, sizeof(stun), 0) == -1) {
			printf("[%s:%d] send error: %s\n", __func__, __LINE__, strerror(errno));
		    }
		    break;

		case STUN_CMD_SYN:
		    {
			char addr1[32], addr2[32];
			struct iphdr* iph = stun.packet + sizeof(struct ethhdr);
			struct tcphdr* tcph = stun.packet + sizeof(struct ethhdr) + sizeof(struct iphdr);

			strcpy(addr1, inet_ntoa(iph->saddr));
			strcpy(addr2, inet_ntoa(iph->daddr));

			memcpy(synConInfo->packet, stun.packet, stun.packetLen);
			synConInfo->packetLen = stun.packetLen;

			SynSend(synConInfo);
			saddr = synConInfo->src_saddr;
			synConInfo->src_saddr = synConInfo->dst_saddr;
			synConInfo->dst_saddr = saddr;
			iph = synConInfo->packet + sizeof(struct ethhdr);
			iph->ttl = ttl;
			tcph = synConInfo->packet + sizeof(struct ethhdr) + sizeof(struct iphdr);
			tcph->syn = 0;
			tcph->ack = 1;
			SynSend(synConInfo);
		    }
		    break;

		case STUN_CMD_HANDSHAKE_OK:
		    gbHandshake = 1;
		    break;

		case STUN_CMD_CONNECT_OK:
		    send(gConnSd, "Server Real OK", 15, 0);
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

    printf("Start HolepDaemonRun\n");
    HolepDaemonRun(address, port, serial);
    printf("End HolepDaemonRun\n");

    return 0;
}
