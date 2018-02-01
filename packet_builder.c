/*
 * Builder for EAP responses.
 *
 * It stores all mandatory information in a private structure,
 * and form a general EAP packet upon request.
 *
 * See include/packet_builder.h for details.
 */
#include <stdlib.h>
#include <arpa/inet.h>

#include "packet_builder.h"
#include "eth_frame.h"
#include "logging.h"
#include "misc.h"
#include "md5.h"

typedef struct _packet_builder_priv {
    FRAME_HEADER frame_header;
    EAP_CONFIG* eap_config;
    uint8_t* md5_seed;
    int seed_len;
} packet_builder_priv;

static PACKET_BUILDER* g_builder = NULL;

#define PRIV ((packet_builder_priv*)(this->priv))

/* Original MentoHUST flavor, with function name changed */
static uint8_t* hash_md5_pwd(uint8_t id, const uint8_t *md5Seed, int seedLen, const char* password)
{
	uint8_t md5Src[80];
	int md5Len = strlen(password);
	md5Src[0] = id;
	memcpy(md5Src + 1, password, md5Len);
	md5Len++;
	memcpy(md5Src + md5Len, md5Seed, seedLen);
	md5Len += seedLen;
	return ComputeHash(md5Src, md5Len);
}

void builder_set_eth_field(struct _packet_builder* this, int field, const uint8_t* val) {
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

void builder_set_eap_fields(struct _packet_builder* this,
                       EAPOL_TYPE eapol_type, EAP_CODE code,
                       EAP_TYPE eap_type, int id, EAP_CONFIG* config) {
    PRIV->frame_header.eapol_hdr.ver[0] = 1; // Force EAPOL version = 1
    PRIV->frame_header.eapol_hdr.type[0] = (unsigned char)eapol_type;
    if (eapol_type != EAP_PACKET) {
        PRIV->frame_header.eapol_hdr.len[0] = 0;
        PRIV->frame_header.eapol_hdr.len[1] = 0;
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
        memmove(PRIV->frame_header.eap_hdr.len, &_eap_packet_len, sizeof(unsigned short));
        memmove(PRIV->frame_header.eapol_hdr.len, &_eap_packet_len, sizeof(unsigned short));

        /* Save for further use */
        PRIV->eap_config = config;
    }
}

void builder_set_eap_md5_seed(struct _packet_builder* this, uint8_t* md5_seed, int seed_len) {
    if (seed_len <= 0) return;

    free(PRIV->md5_seed);
    PRIV->md5_seed = (uint8_t*)malloc(seed_len);
    if (PRIV->md5_seed == NULL) {
        PR_ERRNO("无法为 MD5 种子分配内存空间");
        return;
    }

    memmove(PRIV->md5_seed, md5_seed, seed_len);
    PRIV->seed_len = seed_len;
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

            if (PRIV->md5_seed == NULL || PRIV->seed_len == 0 || PRIV->eap_config == NULL) {
                PR_ERR("构建 Challenge Response 的参数不齐全，请检查是否出现丢包");
                return -1;
            }

            memmove(_challenge, hash_md5_pwd(PRIV->frame_header.eap_hdr.id[0], PRIV->md5_seed,
                                             PRIV->seed_len, PRIV->eap_config->password),
                    MD5_CHALLENGE_DIGEST_SIZE);
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

static PACKET_BUILDER* packet_builder_new() {
    PACKET_BUILDER* this = (PACKET_BUILDER*)malloc(sizeof(PACKET_BUILDER));
    if (this == NULL) {
        PR_ERRNO("数据包生成器主结构内存分配失败");
        return NULL;
    }
    memset(this, 0, sizeof(PACKET_BUILDER));

    /* The priv pointer in packet_builder.h is a packet_builder_priv* here */
    this->priv = (packet_builder_priv*)malloc(sizeof(packet_builder_priv));
    if (this->priv == NULL) {
        PR_ERRNO("数据包生成器私有结构内存分配失败");
        return NULL;
    }
    memset(this->priv, 0, sizeof(packet_builder_priv));

    this->set_eth_field = builder_set_eth_field;
    this->set_eap_fields = builder_set_eap_fields;
    this->set_eap_md5_seed = builder_set_eap_md5_seed;
    this->build_packet = builder_build_packet;

    g_builder = this;
    return this;
}

PACKET_BUILDER* packet_builder_get() {
    return g_builder == NULL ? packet_builder_new() : g_builder;
}

void packet_builder_destroy() {
    if (g_builder) {
        chk_free((void**)&((packet_builder_priv*)g_builder->priv)->md5_seed);
        chk_free((void**)&g_builder->priv);
        chk_free((void**)&g_builder);
    }
}
