#ifndef _MINIEAP_PACKETS_H
#define _MINIEAP_PACKETS_H

#include <stddef.h>
#include <stdint.h>

typedef enum _eap_code{
	EAP_REQUEST = 1,
	EAP_RESPONSE,
	EAP_SUCCESS,
	EAP_FAILURE
} EAP_CODE; // Note: starts from 1

#define EAP_CODE_MIN EAP_REQUEST
#define EAP_CODE_MAX EAP_FAILURE

typedef enum _eapol_packet_type {
	EAP_PACKET = 0,
	EAPOL_START,
	EAPOL_LOGOFF,
	EAPOL_RJ_PROPRIETARY_KEEPALIVE = 0xbf
} EAPOL_TYPE;

#define EAPOL_TYPE_MIN EAP_PACKET
#define EAPOL_TYPE_MAX EAPOL_RJ_PROPRIETARY_KEEPALIVE

typedef enum _eap_type {
	IDENTITY = 1,
	MD5_CHALLENGE = 4
} EAP_TYPE;

typedef struct _ethernet_header {
	unsigned char dest_mac[6];
	unsigned char src_mac[6];
	unsigned char protocol[2];
} ETHERNET_HEADER;

typedef struct _eap_header {
	unsigned char code[1];
	unsigned char id[1];
	unsigned char len[2];
	unsigned char type[1];
} EAP_HEADER;

typedef struct _eapol_header {
	unsigned char ver[1];
	unsigned char type[1];
	unsigned char len[2]; // 802.1Q will be preserved
} EAPOL_HEADER;

typedef struct _frame_header {
	ETHERNET_HEADER eth_hdr;
	EAPOL_HEADER eapol_hdr;
	EAP_HEADER eap_hdr; // Absent in EAPOL-Start and Logoff
} FRAME_HEADER; // Skip the 8021x header manually!

typedef struct _eth_eap_frame {
    size_t actual_len; // Effective length of data in buffer
    size_t buffer_len; // Current buffer length, do not write more than this
    union {
        uint8_t* content;
        FRAME_HEADER* header; // Easier to use without a cast.
                              // But is this "best practice"?
    };
} ETH_EAP_FRAME;

#endif
