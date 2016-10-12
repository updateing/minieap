#include <string.h>
#include <malloc.h>
#include <arpa/inet.h>

#include "packet_builder.h"
#include "eth_frame.h"
#include "logging.h"

typedef struct _packet_builder_priv {
    FRAME_HEADER frame_header;
    EAP_CONFIG* eap_config;
} packet_builder_priv;

#define PRIV ((packet_builder_priv*)(this->priv))
void builder_set_eth_field(struct _packet_builder* this, int field, uint8_t* val) {
    switch (field) {
        case FIELD_DST_MAC:
            memmove(PRIV->frame_header.eth_hdr.dest_mac, val, 6);
            break;
        case FIELD_SRC_MAC:
            memmove(PRIV->frame_header.eth_hdr.src_mac, val, 6);
            break;
        case FIELD_ETH_PROTO:
            memmove(PRIV->frame_header.eth_hdr.protocol, val, 2);
            break;
    }
}

void builder_set_eap_field(struct _packet_builder* this,
                       EAPOL_PACKET_TYPE eapol_type, EAP_CODE code, 
                       EAP_TYPE eap_type, int id, EAP_CONFIG* config) {
    PRIV->frame_header.eapol_hdr.version[0] = 1; // Force EAPOL version = 1
    PRIV->frame_header.eapol_hdr.type[0] = (unsigned char)eapol_type;
    if (eapol_type == EAPOL_START || eapol_type == EAPOL_LOGOFF) {
        PRIV->frame_header.eapol_hdr.length[0] = 0;
        PRIV->frame_header.eapol_hdr.length[1] = 0;
        return;
    } else {
        /*
         * This field only takes standard EAP fields into account, vendor extension
         * does not get counted here.
         */
        unsigned short _eap_packet_len = sizeof(EAP_HEADER) + strlen(config->username);

        /* Wireshark shows that username is appended after MD5 digest */
        if (eap_type == MD5_CHALLENGE) {
            _eap_packet_len += MD5_CHALLENGE_DIGEST_SIZE + 1; // 1 = sizeof(MD5-Value-Size)
        }
        _eap_packet_len = htons(_eap_packet_len);
        PRIV->frame_header.eap_hdr.code[0] = (unsigned char)code;
        PRIV->frame_header.eap_hdr.id[0] = (unsigned char)id;
        PRIV->frame_header.eap_hdr.type[0] = (unsigned char)eap_type;
        memmove(PRIV->frame_header.eap_hdr.length, &_eap_packet_len, sizeof(unsigned short));
        memmove(PRIV->frame_header.eapol_hdr.length, &_eap_packet_len, sizeof(unsigned short));
        
        /* Save for further use */
        PRIV->eap_config = config;
    }
}

int builder_build_packet(struct _packet_builder* this, uint8_t* buffer) {
    int _eapol_type = PRIV->frame_header.eapol_hdr.type[0];
    int _copied_bytes = sizeof(ETHERNET_HEADER) + sizeof(EAPOL_HEADER);
    
    /* Copy the standard fields */
    memmove(buffer, &PRIV->frame_header, sizeof(FRAME_HEADER));
    
    if (_eapol_type != EAP_PACKET) {
        /* EAP header is not valid. Do not indicate we have it */
        return _copied_bytes;
    } else {
        int _eap_type = PRIV->frame_header.eap_hdr.type[0];
        int _username_len = strlen(PRIV->eap_config->username);
        
        /* EAP header is valid here */
        _copied_bytes += sizeof(EAP_HEADER);
        if (_eap_type == MD5_CHALLENGE) {
            uint8_t _challenge[MD5_CHALLENGE_DIGEST_SIZE];
            
            //TODO calculate it
            /* Extra field: MD5-Value-Size (1 byte) */
            buffer[_copied_bytes] = MD5_CHALLENGE_DIGEST_SIZE;
            _copied_bytes += 1;
            
            /* Challenge */
            memmove(buffer + _copied_bytes, _challenge, MD5_CHALLENGE_DIGEST_SIZE);
            _copied_bytes += MD5_CHALLENGE_DIGEST_SIZE;
        }      
                        
        /* Common Routine: Username */
        memmove(buffer + _copied_bytes, PRIV->eap_config->username, _username_len);
        _copied_bytes += _username_len;

        return _copied_bytes;
    }
}

packet_builder* packet_builder_init() {
    packet_builder* this = (packet_builder*)malloc(sizeof(packet_builder));
    if (this < 0) {
        PR_ERRNO("数据包生成器主结构内存分配失败");
        return NULL;
    }
    memset(this, 0, sizeof(packet_builder));
    
    /* The priv pointer in packet_builder.h is a packet_builder_priv* here */
    this->priv = (packet_builder_priv*)malloc(sizeof(packet_builder_priv));
    if (this->priv < 0) {
        PR_ERRNO("数据包生成器私有结构内存分配失败");
        return NULL;
    }
    memset(this->priv, 0, sizeof(packet_builder_priv));
    
    this->set_eth_field = builder_set_eth_field;
    this->set_eap_field = builder_set_eap_field;
    this->build_packet = builder_build_packet;
    return this;
}
