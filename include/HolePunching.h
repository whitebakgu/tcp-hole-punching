#ifndef __HOLE_PUNCHING_H__
#define __HOLE_PUNCHING_H__

typedef enum {
    STUN_CMD_REGISTER = 0,
    STUN_CMD_REQ_INFO,
    STUN_CMD_RESP_INFO,
    STUN_CMD_PORT_PREDICTION,
    STUN_CMD_SYN,
    STUN_CMD_SYN_ACK,
    STUN_CMD_HANDSHAKE_OK,
    STUN_CMD_CONNECT_OK,
    STUN_CMD_PACKET_INFO
} stun_cmd_e;

typedef struct {
    int cmd;
    int serial;
    int bServer;
    struct sockaddr_in saddr;
    char packet[128];
    int packetLen;
} __attribute__((packed)) stun_cmd_t;

#endif
