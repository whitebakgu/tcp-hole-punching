#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <signal.h>

#include "../include/HolePunching.h"
#include "../include/LinuxList.h"

typedef struct {
    struct list_head node;
    int sd;
    struct sockaddr_in saddr;
} peer_sd_t;

typedef struct {
    int sd;
    struct sockaddr_in src_saddr;
    struct sockaddr_in dst_saddr;
    char packet[128];
    int packetLen;
} con_info_t;

typedef struct {
    struct list_head node;
    int serial;
    int conSd;
    int cliSd;
    unsigned short serPort[3];
    unsigned short cliPort[3];
    struct sockaddr_in serAddr;
    struct sockaddr_in cliAddr;
    int serPacketLen;
    int bSerHand;
    int bCliHand;
    int bConSerOk;
    int bConCliOk;
} server_side_t;

struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

int gbRun = 1;

struct list_head gPeerSds;
pthread_mutex_t gPeerSdsMutex;

struct list_head gServers;

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
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = conInfo->src_saddr.sin_addr.s_addr;
    iph->daddr = conInfo->dst_saddr.sin_addr.s_addr;

    tcph->source = conInfo->src_saddr.sin_port;
    tcph->dest = conInfo->dst_saddr.sin_port;
    memcpy(&tcph->seq, &tcphPack->seq, sizeof(tcph->seq));
    memcpy(&tcph->ack_seq, &tcphPack->ack_seq, sizeof(tcph->ack_seq));
    tcph->doff = 5;
    tcph->syn = 1;
    tcph->ack = 1;
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

void* ProcessMessage(void* arg)
{
    peer_sd_t *pos, *n;
    server_side_t *servPos, *servN;

    INIT_LIST_HEAD(&gServers);

    while(gbRun) {
	pthread_mutex_lock(&gPeerSdsMutex);

	if(list_empty(&gPeerSds)) {
	    pthread_mutex_unlock(&gPeerSdsMutex);

	    usleep(10000);
	    continue;
	} else {
	    fd_set fds;
	    struct timeval tv;
	    int maxSd = 0;
	    int ret;

	    FD_ZERO(&fds);

	    list_for_each_entry(pos, &gPeerSds, node) {
		FD_SET(pos->sd, &fds);

		if(pos->sd > maxSd) {
		    maxSd = pos->sd;
		}
	    }

	    pthread_mutex_unlock(&gPeerSdsMutex);

	    tv.tv_sec = 0;
	    tv.tv_usec = 10000;

	    ret = select(maxSd + 1, &fds, NULL, NULL, &tv);

	    if(ret == -1) {
		printf("[%s:%d] select error: %s\n", __func__, __LINE__, strerror(errno));
	    } else if(ret) {
		stun_cmd_t stun;
		server_side_t *server;

		memset(&stun, 0, sizeof(stun));

		pthread_mutex_lock(&gPeerSdsMutex);

		list_for_each_entry_safe(pos, n, &gPeerSds, node) {
		    if(FD_ISSET(pos->sd, &fds)) {
			if(recv(pos->sd, &stun, sizeof(stun), 0) != sizeof(stun)) {
			    printf("[%s:%d] recv error: %s\n", __func__, __LINE__, strerror(errno));
			    list_del(&pos->node);

			    list_for_each_entry(servPos, &gServers, node) {
				if(servPos->conSd == pos->sd) {
				    list_del(&servPos->node);
				    free(servPos);
				    break;
				}
			    }

			    close(pos->sd);
			    free(pos);
			} else {
			    switch(stun.cmd) {
				case STUN_CMD_REGISTER:
				    if(!stun.serial) {
					break;
				    }

				    server = malloc(sizeof(*server));
				    memset(server, 0, sizeof(*server));

				    if(server) {
					server->serial = stun.serial;
					server->conSd = pos->sd;
					list_add_tail(&server->node, &gServers);
				    }
				    break;

				case STUN_CMD_REQ_INFO:
				    list_for_each_entry(servPos, &gServers, node) {
					if(servPos->serial == stun.serial) {
					    servPos->cliSd = pos->sd;
					    while(send(pos->sd, &stun, sizeof(stun), 0) == -1) {
						if(errno == EAGAIN || errno == EWOULDBLOCK) {
						    continue;
						}

						printf("[%s:%d] send error: %s\n", __func__, __LINE__, strerror(errno));
					    }

					    while(send(servPos->conSd, &stun, sizeof(stun), 0) == -1) {
						if(errno == EAGAIN || errno == EWOULDBLOCK) {
						    continue;
						}

						printf("[%s:%d] send error: %s\n", __func__, __LINE__, strerror(errno));
					    }
					}
				    }
				    break;

				case STUN_CMD_PORT_PREDICTION:
				    list_for_each_entry(servPos, &gServers, node) {
					if(servPos->serial == stun.serial) {
					    unsigned short* port = stun.bServer ? servPos->serPort : servPos->cliPort;
					    int i;

					    for(i = 0; i < 3; i++) {
						if(!port[i]) {
						    port[i] = ntohs(pos->saddr.sin_port);
						    break;
						}
					    }

					    if(i >= 2) {
						int sub1 = port[1] - port[0], sub2 = port[2] - port[1];
						unsigned short predictedPort = ntohs(pos->saddr.sin_port) + sub2 + (sub2 - sub1);

						if(predictedPort > 65535) {
						    stun.cmd = STUN_CMD_REQ_INFO;
						    while(send(pos->sd, &stun, sizeof(stun), 0) == -1) {
							if(errno == EAGAIN || errno == EWOULDBLOCK) {
							    continue;
							}

							printf("[%s:%d] send error: %s\n", __func__, __LINE__, strerror(errno));
						    }

						    memset(port, 0, sizeof(servPos->serPort));
						    break;
						}

						if(stun.bServer) {
						    servPos->serAddr.sin_addr = pos->saddr.sin_addr;
						    servPos->serAddr.sin_port = htons(predictedPort);
						} else {
						    servPos->cliAddr.sin_addr = pos->saddr.sin_addr;
						    servPos->cliAddr.sin_port = htons(predictedPort);
						}

						if(servPos->serAddr.sin_port && servPos->cliAddr.sin_port) {
						    stun.cmd = STUN_CMD_RESP_INFO;
						    printf("Server : %s:%d\n", inet_ntoa(servPos->serAddr.sin_addr.s_addr), ntohs(servPos->serAddr.sin_port));
						    printf("Client : %s:%d\n", inet_ntoa(servPos->cliAddr.sin_addr.s_addr), ntohs(servPos->cliAddr.sin_port));

						    stun.saddr = servPos->cliAddr;
						    while(send(servPos->conSd, &stun, sizeof(stun), 0) == -1) {
							if(errno == EAGAIN || errno == EWOULDBLOCK) {
							    continue;
							}

							printf("[%s:%d] send error: %s\n", __func__, __LINE__, strerror(errno));
						    }
						}
					    }
					    break;
					}
				    }
				    break;

				case STUN_CMD_RESP_INFO:
				    list_for_each_entry(servPos, &gServers, node) {
					if(servPos->serial == stun.serial) {
					    stun.saddr = servPos->serAddr;
					    while(send(servPos->cliSd, &stun, sizeof(stun), 0) == -1) {
						if(errno == EAGAIN || errno == EWOULDBLOCK) {
						    continue;
						}

						printf("[%s:%d] send error: %s\n", __func__, __LINE__, strerror(errno));
					    }
					}
				    }
				    break;

				case STUN_CMD_SYN:
				    list_for_each_entry(servPos, &gServers, node) {
					if(servPos->serial == stun.serial && servPos->serAddr.sin_port && servPos->cliAddr.sin_port) {
					    char addr1[32], addr2[32];
					    struct iphdr* iph = stun.packet + sizeof(struct ethhdr);
					    struct tcphdr* tcph = stun.packet + sizeof(struct ethhdr) + sizeof(struct iphdr);


					    strcpy(addr1, inet_ntoa(iph->saddr));
					    strcpy(addr2, inet_ntoa(iph->daddr));

					    while(send(servPos->conSd, &stun, sizeof(stun), 0) != sizeof(stun)) {
						if(errno == EAGAIN || errno == EWOULDBLOCK) {
						    continue;
						}

						printf("[%s:%d] send error: %s\n", __func__, __LINE__, strerror(errno));
					    }
					}
				    }
				    break;

				case STUN_CMD_SYN_ACK:
				    list_for_each_entry(servPos, &gServers, node) {
					if(servPos->serial == stun.serial && servPos->serAddr.sin_port && servPos->cliAddr.sin_port) {
					    con_info_t* conInfo = malloc(sizeof(con_info_t));

					    conInfo->src_saddr = servPos->serAddr;
					    conInfo->dst_saddr = servPos->cliAddr;
					    memcpy(conInfo->packet, stun.packet, stun.packetLen);
					    conInfo->packetLen = servPos->serPacketLen;
					    SynSend(conInfo);
					}
				    }
				    break;

				case STUN_CMD_HANDSHAKE_OK:
				    list_for_each_entry(servPos, &gServers, node) {
					if(servPos->serial == stun.serial && servPos->serAddr.sin_port && servPos->cliAddr.sin_port) {
					    if(stun.bServer) {
						servPos->bSerHand = 1;
					    } else {
						servPos->bCliHand = 1;
					    }

					    if(servPos->bSerHand && servPos->bCliHand) {
						while(send(servPos->conSd, &stun, sizeof(stun), 0) != sizeof(stun)) {
						    if(errno == EAGAIN || errno == EWOULDBLOCK) {
							continue;
						    }
						    printf("[%s:%d] send error: %s\n", __func__, __LINE__, strerror(errno));
						}

						while(send(servPos->cliSd, &stun, sizeof(stun), 0) != sizeof(stun)) {
						    if(errno == EAGAIN || errno == EWOULDBLOCK) {
							continue;
						    }
						    printf("[%s:%d] send error: %s\n", __func__, __LINE__, strerror(errno));
						}
					    }
					}
				    }
				    break;

				case STUN_CMD_CONNECT_OK:
				    list_for_each_entry(servPos, &gServers, node) {
					if(servPos->serial == stun.serial && servPos->serAddr.sin_port && servPos->cliAddr.sin_port) {
					    if(stun.bServer) {
						servPos->bConSerOk = 1;
					    } else {
						servPos->bConCliOk = 1;
					    }

					    if(servPos->bConSerOk && servPos->bConCliOk) {
						while(send(servPos->conSd, &stun, sizeof(stun), 0) != sizeof(stun)) {
						    if(errno == EAGAIN || errno == EWOULDBLOCK) {
							continue;
						    }
						    printf("[%s:%d] send error: %s\n", __func__, __LINE__, strerror(errno));
						}

						while(send(servPos->cliSd, &stun, sizeof(stun), 0) != sizeof(stun)) {
						    if(errno == EAGAIN || errno == EWOULDBLOCK) {
							continue;
						    }
						    printf("[%s:%d] send error: %s\n", __func__, __LINE__, strerror(errno));
						}
					    }
					}
				    }
				    break;

				case STUN_CMD_PACKET_INFO:
				    {
					char addr1[32], addr2[32];
					struct iphdr* iph = stun.packet + sizeof(struct ethhdr);
					struct tcphdr* tcph = stun.packet + sizeof(struct ethhdr) + sizeof(struct iphdr);

					if(ntohs(tcph->source) == 55555 || ntohs(tcph->dest) == 55555) {
					    break;
					}

					strcpy(addr1, inet_ntoa(iph->saddr));
					strcpy(addr2, inet_ntoa(iph->daddr));

					printf("%s:%d -> %s:%d seq(%x) ack_seq(%x)", addr1, ntohs(tcph->source), addr2, ntohs(tcph->dest), ntohl(tcph->seq), ntohl(tcph->ack_seq));
					if(tcph->syn) {
					    printf(" SYN");
					}
					if(tcph->ack) {
					    printf(" ACK");
					}
					if(tcph->fin) {
					    printf(" FIN");
					}
					if(tcph->rst) {
					    printf(" RST");
					}
					if(tcph->psh) {
					    printf(" PSH");
					}
					if(tcph->urg) {
					    printf(" URG");
					}

					if(stun.packetLen > sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr)) {
					    stun.packet[127] = '\0';
					    printf(" %s", (char*)tcph + sizeof(struct tcphdr));
					}

					printf("\n");
				    }
				    break;
				default:
				    printf("[%s:%d] unknown stun command\n", __func__, __LINE__);
				    break;
			    }
			}
		    }
		}

		pthread_mutex_unlock(&gPeerSdsMutex);
	    }
	}
    }

    list_for_each_entry_safe(servPos, servN, &gServers, node) {
	list_del(&servPos->node);
	free(servPos);
    }

    return NULL;
}

void StunDaemonRun(unsigned short portNum)
{
    int sdStun = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in saddr, peerAddr;
    peer_sd_t *pos, *n;
    pthread_t msgThr;
    socklen_t addrLen;
    int flag;

    if(sdStun == -1) {
	printf("[%s:%d] socket error: %s\n", __func__, __LINE__, strerror(errno));
	return;
    }

    flag = 1;
    if(setsockopt(sdStun, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) == -1) {
	printf("[%s:%d] setsockopt error: %s\n", __func__, __LINE__, strerror(errno));
	goto exit;
    }

    pthread_mutex_init(&gPeerSdsMutex, NULL);

    bzero(&saddr, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = htonl(INADDR_ANY);
    saddr.sin_port = htons(portNum);

    if(bind(sdStun, (struct sockaddr*)&saddr, sizeof(saddr)) == -1) {
	printf("[%s:%d] bind error: %s\n", __func__, __LINE__, strerror(errno));
	goto exit;
    }

    if(listen(sdStun, 5) == -1) {
	printf("[%s:%d] listen error: %s\n", __func__, __LINE__, strerror(errno));
	goto exit;
    }

    INIT_LIST_HEAD(&gPeerSds);

    if(pthread_create(&msgThr, NULL, ProcessMessage, NULL) != 0) {
	printf("[%s:%d] pthread_create error\n", __func__, __LINE__);
	goto exit;
    }

    addrLen = sizeof(peerAddr);
    while(gbRun) {
	fd_set fds;
        struct timeval tv;
	int maxSd = 0;
	int ret;

	FD_ZERO(&fds);
	FD_SET(sdStun, &fds);

	tv.tv_sec = 0;
	tv.tv_usec = 10000;

	ret = select(sdStun + 1, &fds, NULL, NULL, &tv);

	if(ret == -1) {
	    printf("[%s:%d] select error: %s\n", __func__, __LINE__, strerror(errno));
	} else if(ret) {
	    int sdPeer = accept(sdStun, (struct sockaddr*)&peerAddr, &addrLen);
	    stun_cmd_t stun;
	    peer_sd_t* pSdtPeer;

	    if(sdPeer == -1) {
		printf("[%s:%d] accept error: %s\n", __func__, __LINE__, strerror(errno));
		goto exit;
	    }

	    fcntl(sdPeer, F_SETFL, fcntl(sdPeer, F_GETFL, 0) | O_NONBLOCK);

	    pSdtPeer = malloc(sizeof(*pSdtPeer));
	    if(pSdtPeer) {
		pSdtPeer->sd = sdPeer;
		pSdtPeer->saddr = peerAddr;

		pthread_mutex_lock(&gPeerSdsMutex);

		list_add_tail(&pSdtPeer->node, &gPeerSds);

		pthread_mutex_unlock(&gPeerSdsMutex);
	    } else {
		printf("[%s:%d] malloc error\n", __func__, __LINE__);
		close(sdPeer);
	    }
	}
    }

exit:
    pthread_mutex_destroy(&gPeerSdsMutex);

    if(sdStun != -1) {
	close(sdStun);
    }

    list_for_each_entry_safe(pos, n, &gPeerSds, node) {
	close(pos->sd);
	list_del(&pos->node);
	free(pos);
    }
}

void PrintHelp(char* argv[])
{
    printf("Usage: %s -p {port number}\n"
	    "  -p port : Stun server port\n"
	    "  -h      : Print this usage\n", argv[0]);
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
    unsigned short port = 0;
    struct sigaction sigaInst;

    while((opt = getopt(argc, argv, "hp:")) != -1) {
	switch(opt) {
	    case 'p':
		port = atoi(optarg);
		break;

	    case 'h':
	    default:
		PrintHelp(argv);
		return -1;
	}
    }

    if(!port) {
	PrintHelp(argv);
	return -1;
    }

    sigaInst.sa_flags = 0;
    sigemptyset(&sigaInst.sa_mask);
    sigaddset(&sigaInst.sa_mask, SIGTERM);
    sigaddset(&sigaInst.sa_mask, SIGINT);

    sigaInst.sa_handler = SigHandler;
    sigaction(SIGTERM, &sigaInst, NULL);
    sigaction(SIGINT, &sigaInst, NULL);

    printf("Start StunDaemonRun\n");
    StunDaemonRun(port);
    printf("End StunDaemonRun\n");

    return 0;
}
