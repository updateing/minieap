#ifndef _MINIEAP_PACKETS_H
#define _MINIEAP_PACKETS_H

enum {
	EAP_REQUEST = 1,
	EAP_RESPONSE,
	EAP_SUCCESS,
	EAP_FAILURE
} EAP_CODE; // Note: starts from 1

#define EAP_CODE_MIN EAP_REQUEST
#define EAP_CODE_MAX EAP_FAILURE

enum {
	EAP_PACKET = 0,
	EAPOL_START,
	EAPOL_LOGOFF,
	EAPOL_RJ_PROPRIETARY_KEEPALIVE = 0xbf
} EAPOL_PACKET_TYPE;

#define EAPOL_TYPE_MIN EAP_PACKET
#define EAPOL_TYPE_MAX EAPOL_RJ_PROPRIETARY_KEEPALIVE

enum {
	IDENTITY = 1,
	MD5_CHALLENGE = 4
} EAP_TYPE;

typedef struct {
	unsigned char dest_mac[6];
	unsigned char src_mac[6];
	unsigned char protocol[2];
} ETHERNET_HEADER;

typedef struct {
	unsigned char code[1];
	unsigned char id[1];
	unsigned char length[2];
	unsigned char type[1];
} EAP_HEADER;

typedef struct {
	unsigned char version[1];
	unsigned char type[1];
	unsigned char length[2]; // 802.1Q will be preserved
} EAPOL_HEADER;

typedef struct {
	ETHERNET_HEADER eth_hdr;
	EAPOL_HEADER eapol_hdr;
	EAP_HEADER eap_hdr; // Absent in EAPOL-Start and Logoff
} FRAME_HEADER; // Skip the 8021x header manually!

typedef struct _eth_eap_frame {
    size_t len;
    union {
        uint8_t* content;
        FRAME_HEADER* header; // Easier to use without a cast.
                              // But is this "best practice"?
    }
} ETH_EAP_FRAME;

        
