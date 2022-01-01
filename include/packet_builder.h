#ifndef _MINIEAP_PACKET_BUILDER_H
#define _MINIEAP_PACKET_BUILDER_H

#include <stdint.h>
#include "config.h"
#include "eth_frame.h"

/* Standard, do not modify */
#define MD5_CHALLENGE_DIGEST_SIZE 16

/*
 * A Packet Builder
 *
 * I don't want to make this pluggable since it's the standard EAP implementation.
 * This builder does not provide manipulation on packets either.
 *
 * If you want to change the structure of packets, make an packet plugin instead.
 */
typedef struct _packet_builder {
    #define FIELD_DST_MAC (1 << 0)
    #define FIELD_SRC_MAC (1 << 1)
    #define FIELD_ETH_PROTO (1 << 2)
    /*
     * Sets above 3 ethernet frame fields
     * We know the length, thus no length param
     * Can be used to set up internal structure
     */
    void (*set_eth_field)(struct _packet_builder* this, int field, const uint8_t* val);

    /*
     * Sets EAP(OL) related fields
     * Use EAP_CONFIG for credentials
     * Can be used to set up internal structure
     *
     * Note:
     *   1. EAP_CODE and EAP_CONFIG are not used in EAPOL Start and Logoff packets
     *   2. ID needs to match the corresponging EAP-Request packet
     */
    void (*set_eap_fields)(struct _packet_builder* this,
                       EAPOL_TYPE eapol_type, EAP_CODE code,
                       EAP_TYPE eap_type, int id, EAP_CONFIG* config);

    /*
     * Sets the MD5 seed required for EAP-Response-MD5-Challenge
     *
     * MUST BE CALLED before building a challenge response!
     */
    void (*set_eap_md5_seed)(struct _packet_builder* this, uint8_t* md5_seed, int seed_len);

    /*
     * Build the packet into buffer based on information given previously
     *
     * Note: this may involve heavy calculations
     * Return: the actual length of the packet
     */
    int (*build_packet)(struct _packet_builder* this, uint8_t* buffer);

    /*
     * Builder internal use
     * Can be used to save information
     */
    void* priv;
} PACKET_BUILDER;

/*
 * Get an instance of packet builder (singleton)
 *
 * Return: an instance of this struct, with all methods above set up
 */
PACKET_BUILDER* packet_builder_get();

/*
 * Destroy the instance
 * Can be used to free memory
 */
void packet_builder_destroy();
#endif
