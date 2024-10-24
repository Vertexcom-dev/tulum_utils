/*
 * MIT License
 *
 * Copyright (c) 2024 Vertexcom
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
// Implementation of Mstar specific MME send/receive

// Avoid unnecessary warnings with VC
#define _CRT_SECURE_NO_WARNINGS 1

#include "pcap.h"

// To include Mstar specific MMEs
#include "hpav_api.h"
#include "hpav_mme.h"
#include "hpav_mtk_api.h"
#include "hpav_utils.h"

#include "stdio.h"

// Special encode for Mstar
#define HPAV_ENCODE_MTK_MME_IMPL(MME_NAME, MMETYPE_REQ)                        \
    struct hpav_mme_packet *hpav_encode_##MME_NAME(                            \
        unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE],                      \
        unsigned char src_mac_addr[ETH_MAC_ADDRESS_SIZE],                      \
        struct hpav_##MME_NAME *request) {                                     \
        /* Basic method : allocate right size, build the header, copy the      \
         * request */                                                          \
        /* This method works for all MME with fixed maximum data content */    \
        /* For MMEs with variable maximum size, a specific function is         \
         * required */                                                         \
        unsigned char *new_mme = NULL;                                         \
        unsigned int mme_size = sizeof(struct hpav_mtk_mme_header) +           \
                                sizeof(struct hpav_##MME_NAME);                \
        struct hpav_mme_packet *new_packet =                                   \
            (struct hpav_mme_packet *)malloc(sizeof(struct hpav_mme_packet));  \
        struct hpav_mtk_mme_frame *mme_frame = NULL;                           \
        new_mme = (unsigned char *)malloc(mme_size);                           \
        mme_frame = (struct hpav_mtk_mme_frame *)new_mme;                      \
        mme_frame->header.mmv = 0x01; /* HPAV 1.1 */                           \
        mme_frame->header.mmtype = MMETYPE_REQ;                                \
        mme_frame->header.fmi_nf_fn = 0x00;                                    \
        mme_frame->header.fmi_fmsn = 0x00;                                     \
        mme_frame->header.oui[0] = 0x00;                                       \
        mme_frame->header.oui[1] = 0x13;                                       \
        mme_frame->header.oui[2] = 0xD7;                                       \
        memcpy(&mme_frame->unknown_mtk_mme, request,                           \
               sizeof(struct hpav_##MME_NAME));                                \
        /* Required byte ordering correction should take place here */         \
        /* Add another function call hpav_hton_MME */                          \
        new_packet->data_size = mme_size;                                      \
        new_packet->data = new_mme;                                            \
        memcpy(new_packet->dst_mac_addr, sta_mac_addr, ETH_MAC_ADDRESS_SIZE);  \
        memcpy(new_packet->src_mac_addr, src_mac_addr, ETH_MAC_ADDRESS_SIZE);  \
        new_packet->next = NULL;                                               \
        return new_packet;                                                     \
    }

// Special encode for JiangSu
#define HPAV_ENCODE_JIANGSU_MME_IMPL(MME_NAME, MMETYPE_REQ)                    \
    struct hpav_mme_packet *hpav_encode_##MME_NAME(                            \
        unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE],                      \
        unsigned char src_mac_addr[ETH_MAC_ADDRESS_SIZE],                      \
        struct hpav_##MME_NAME *request) {                                     \
        /* Basic method : allocate right size, build the header, copy the      \
         * request */                                                          \
        /* This method works for all MME with fixed maximum data content */    \
        /* For MMEs with variable maximum size, a specific function is         \
         * required */                                                         \
        unsigned char *new_mme = NULL;                                         \
        unsigned int mme_size = sizeof(struct hpav_mtk_mme_header) +           \
                                sizeof(struct hpav_##MME_NAME);                \
        struct hpav_mme_packet *new_packet =                                   \
            (struct hpav_mme_packet *)malloc(sizeof(struct hpav_mme_packet));  \
        struct hpav_mtk_mme_frame *mme_frame = NULL;                           \
        new_mme = (unsigned char *)malloc(mme_size);                           \
        mme_frame = (struct hpav_mtk_mme_frame *)new_mme;                      \
        mme_frame->header.mmv = 0x01; /* HPAV 1.1 */                           \
        mme_frame->header.mmtype = MMETYPE_REQ;                                \
        mme_frame->header.fmi_nf_fn = 0x00;                                    \
        mme_frame->header.fmi_fmsn = 0x00;                                     \
        mme_frame->header.oui[0] = 0x4A;                                       \
        mme_frame->header.oui[1] = 0x53;                                       \
        mme_frame->header.oui[2] = 0x43;                                       \
        memcpy(&mme_frame->unknown_mtk_mme, request,                           \
               sizeof(struct hpav_##MME_NAME));                                \
        /* Required byte ordering correction should take place here */         \
        /* Add another function call hpav_hton_MME */                          \
        new_packet->data_size = mme_size;                                      \
        new_packet->data = new_mme;                                            \
        memcpy(new_packet->dst_mac_addr, sta_mac_addr, ETH_MAC_ADDRESS_SIZE);  \
        memcpy(new_packet->src_mac_addr, src_mac_addr, ETH_MAC_ADDRESS_SIZE);  \
        new_packet->next = NULL;                                               \
        return new_packet;                                                     \
    }

#define HPAV_DECODE_MTK_MME_IMPL(MME_NAME)                                     \
    struct hpav_##MME_NAME *hpav_decode_##MME_NAME(                            \
        struct hpav_mme_packet *packets) {                                     \
        /* Last user level MME for chaining */                                 \
        struct hpav_##MME_NAME *last_mme = NULL;                               \
        /* Returned data */                                                    \
        struct hpav_##MME_NAME *returned_mme = NULL;                           \
                                                                               \
        /* Same function for a lot of MMEs : just copy the data to user level  \
           data structure (we try                                              \
           to keep data in order of reception) */                              \
        while (packets != NULL) {                                              \
            struct hpav_##MME_NAME *new_mme =                                  \
                malloc(sizeof(struct hpav_##MME_NAME));                        \
            /* The CNF struct contains non ETH level data that we don't need   \
               to copy                                                         \
               The MME data contains the MME header, we should read past it */ \
            hpav_smart_copy_##MME_NAME(                                        \
                new_mme, packets->data + sizeof(struct hpav_mme_header) + 3,   \
                packets->data_size - sizeof(struct hpav_mme_header) - 3);      \
            new_mme->next = NULL;                                              \
            memcpy(new_mme->sta_mac_addr, packets->src_mac_addr,               \
                   ETH_MAC_ADDRESS_SIZE);                                      \
                                                                               \
            /* Required byte ordering correction should take place here */     \
            /* Add another function call hpav_ntoh_MME */                      \
                                                                               \
            if (last_mme == NULL) {                                            \
                returned_mme = new_mme;                                        \
            } else {                                                           \
                last_mme->next = new_mme;                                      \
            }                                                                  \
            last_mme = new_mme;                                                \
            packets = packets->next;                                           \
        }                                                                      \
        return returned_mme;                                                   \
    }

HPAV_SMART_COPY_IMPL(mtk_vs_set_nvram_cnf);
HPAV_SMART_COPY_IMPL(mtk_vs_get_version_cnf);
HPAV_SMART_COPY_IMPL(mtk_vs_reset_cnf);
HPAV_SMART_COPY_IMPL(mtk_vs_reset_rsp);
HPAV_SMART_COPY_IMPL(mtk_vs_get_nvram_cnf);
HPAV_SMART_COPY_IMPL(mtk_vs_get_tonemask_cnf);
HPAV_SMART_COPY_IMPL(mtk_vs_get_eth_phy_cnf);
HPAV_SMART_COPY_IMPL(mtk_vs_eth_stats_cnf);
HPAV_SMART_COPY_IMPL(mtk_vs_get_status_cnf);
HPAV_SMART_COPY_IMPL(mtk_vs_get_link_stats_cnf);
HPAV_SMART_COPY_IMPL(mtk_vs_set_capture_state_cnf);
HPAV_SMART_COPY_IMPL(mtk_vs_spi_stats_cnf);
HPAV_SMART_COPY_IMPL(mtk_vs_pwm_generation_cnf);
HPAV_SMART_COPY_IMPL(vc_vs_set_sniffer_conf_cnf);
HPAV_SMART_COPY_IMPL(vc_vs_set_remote_access_cnf);
HPAV_SMART_COPY_IMPL(vc_vs_get_remote_access_cnf);

// HPAV_SMART_COPY_IMPL(mtk_vs_get_nw_info_cnf);

int hpav_smart_copy_mtk_vs_get_nw_info_cnf(
    struct hpav_mtk_vs_get_nw_info_cnf *response, unsigned char *mme_data,
    unsigned int mme_data_size) {
    // MME data size is ignored. We just match the prototype of memcpy to
    // simplify the code
    // Number of networks stats entries is the first char
    memcpy(&response->nid, mme_data, HPAV_NID_SIZE);
    mme_data += HPAV_NID_SIZE;
    response->snid = *mme_data;
    ++mme_data;
    response->cco_tei = *mme_data;
    ++mme_data;
    memcpy(&response->cco_mac_addr, mme_data, ETH_MAC_ADDRESS_SIZE);
    mme_data += ETH_MAC_ADDRESS_SIZE;
    response->num_nws = *mme_data;
    mme_data++;
    if (response->num_nws != 0) {
        response->nwinfo = malloc(response->num_nws *
                                  sizeof(struct hpav_mtk_vs_get_nw_info_entry));
        memcpy(response->nwinfo, mme_data,
               response->num_nws *
                   sizeof(struct hpav_mtk_vs_get_nw_info_entry));
    } else
        response->nwinfo = NULL;

    return 0;
}

// Special smart copy
int hpav_smart_copy_mtk_vs_get_tonemap_cnf(
    struct hpav_mtk_vs_get_tonemap_cnf *response, unsigned char *mme_data,
    unsigned int mme_data_size) {
    unsigned int left_mme_data_size = mme_data_size;

    // Fixed fields at the beginning of the structure
    response->result = *mme_data;
    mme_data++;
    left_mme_data_size--;
    response->beacon_delta = *((unsigned int *)mme_data);
    mme_data += sizeof(unsigned int);
    left_mme_data_size -= sizeof(unsigned int);
    response->int_id = *mme_data;
    mme_data++;
    left_mme_data_size--;
    response->tmi_default = *mme_data;
    mme_data++;
    left_mme_data_size--;
    // Variable size arrays
    response->tmi_length = *mme_data;
    mme_data++;
    left_mme_data_size--;
    response->tmi_data = malloc(response->tmi_length);
    memcpy(response->tmi_data, mme_data, response->tmi_length);
    mme_data += response->tmi_length;
    left_mme_data_size -= response->tmi_length;

    response->int_length = *mme_data;
    mme_data++;
    left_mme_data_size--;
    response->int_data = malloc(response->int_length *
                                sizeof(struct hpav_mtk_tonemap_int_entry));
    memcpy(response->int_data, mme_data,
           response->int_length * sizeof(struct hpav_mtk_tonemap_int_entry));
    mme_data +=
        response->int_length * sizeof(struct hpav_mtk_tonemap_int_entry);
    left_mme_data_size -=
        response->int_length * sizeof(struct hpav_mtk_tonemap_int_entry);

    // Other fixed fields
    response->tmi = *mme_data;
    mme_data++;
    left_mme_data_size--;
    response->tm_rx_gain = *mme_data;
    mme_data++;
    left_mme_data_size--;
    response->tm_fec = *mme_data;
    mme_data++;
    left_mme_data_size--;
    response->tm_gi = *mme_data;
    mme_data++;
    left_mme_data_size--;
    response->tm_phy_rate = *((unsigned int *)mme_data);
    mme_data += sizeof(unsigned int);
    left_mme_data_size -= sizeof(unsigned int);
    response->carrier_group = *mme_data;
    mme_data++;
    left_mme_data_size--;

    // Modulation list
    response->tonemap_length = *((unsigned short *)mme_data);
    mme_data += sizeof(unsigned short);
    left_mme_data_size -= sizeof(unsigned short);

    memset(response->modulation_list, 0, MTK_MODULATION_LIST_MAX_SIZE);
    if (left_mme_data_size > 0)
        memcpy(&response->modulation_list[0], mme_data, left_mme_data_size);

    return 0;
}

int hpav_smart_copy_mtk_vs_get_snr_cnf(struct hpav_mtk_vs_get_snr_cnf *response,
                                       unsigned char *mme_data,
                                       unsigned int mme_data_size) {
    // Fixed fields at the beginning of the structure
    response->result = *mme_data;
    mme_data++;
    response->int_id = *mme_data;
    mme_data++;
    response->int_length = *mme_data;
    mme_data++;
    // Variable size arrays
    response->int_data = malloc(response->int_length * sizeof(unsigned short));
    memcpy(response->int_data, mme_data,
           response->int_length * sizeof(unsigned short));
    mme_data += response->int_length * sizeof(unsigned short);
    response->tm_ber = *((unsigned short *)mme_data);
    mme_data += sizeof(unsigned short);
    response->carrier_group = *((unsigned char *)mme_data);
    mme_data += sizeof(unsigned char);
    // SNR list
    memcpy(&response->snr_list[0], mme_data,
           MTK_SNR_LIST_MAX_SIZE * sizeof(response->snr_list[0]));

    return 0;
}

int hpav_smart_copy_mtk_vs_file_access_cnf(
    struct hpav_mtk_vs_file_access_cnf *new_mme, unsigned char *mme_data,
    unsigned int mme_data_size) {
    memcpy(new_mme, mme_data, mme_data_size);
    if (new_mme->length < HPAV_MTK_VS_FILE_ACCESS_CNF_DATA_MAX_LEN)
        memset(new_mme->data + new_mme->length, 0,
               HPAV_MTK_VS_FILE_ACCESS_CNF_DATA_MAX_LEN - new_mme->length);
    return 0;
}

int hpav_smart_copy_mtk_vs_get_pwm_stats_cnf(
    struct hpav_mtk_vs_get_pwm_stats_cnf *response, unsigned char *mme_data,
    unsigned int mme_data_size) {
    response->mstatus = *mme_data;
    mme_data++;
    response->pwm_freq = *((unsigned short *)mme_data);
    mme_data = mme_data + 2;
    response->pwm_duty_cycle = *((unsigned short *)mme_data);
    mme_data = mme_data + 2;
    response->pwm_volt = *((unsigned short *)mme_data);
    mme_data = mme_data + 2;
    response->pwm_saradc = *((unsigned short*)mme_data);

    return 0;
}

int hpav_smart_copy_mtk_vs_get_pwm_conf_cnf(
    struct hpav_mtk_vs_get_pwm_conf_cnf *response, unsigned char *mme_data,
    unsigned int mme_data_size) {
    response->pwm_mode = *mme_data;
    mme_data++;
    response->pwm_measures = *mme_data;
    mme_data++;
    response->pwm_period = *((unsigned short *)mme_data);
    mme_data = mme_data + 2;
    response->pwm_freq_thr = *((unsigned short *)mme_data);
    mme_data = mme_data + 2;
    response->pwm_duty_cycle_thr = *((unsigned short *)mme_data);
    mme_data = mme_data + 2;
    response->pwm_volt_thr = *((unsigned short *)mme_data);
    mme_data = mme_data + 2;
    response->pwm_saradc_lsb = *((unsigned short*)mme_data);
    mme_data = mme_data + 2;
    response->pwm_voltage_bias = *((unsigned short*)mme_data);

    return 0;
}

int hpav_smart_copy_mtk_vs_set_pwm_conf_cnf(
    struct hpav_mtk_vs_set_pwm_conf_cnf *response, unsigned char *mme_data,
    unsigned int mme_data_size) {
    response->mstatus = *mme_data;

    return 0;
}

int hpav_smart_copy_mtk_vs_set_tx_cali_cnf(
    struct hpav_mtk_vs_set_tx_cali_cnf *response, unsigned char *mme_data,
    unsigned int mme_data_size) {
    response->result = *mme_data;

    return 0;
}

int hpav_smart_copy_mtk_vs_set_tx_cali_ind(
    struct hpav_mtk_vs_set_tx_cali_ind *response, unsigned char *mme_data,
    unsigned int mme_data_size) {
    response->spectrum_idx = *((unsigned short *)mme_data);
    mme_data = mme_data + 2;
    memcpy(response->result, mme_data, SNIF_GP_CAL_NUM_OF_SPECTRUM);
    return 0;
}

HPAV_FREE_STRUCT_IMPL(mtk_vs_set_nvram_cnf);
HPAV_FREE_STRUCT_IMPL(mtk_vs_get_version_cnf);
HPAV_FREE_STRUCT_IMPL(mtk_vs_reset_cnf);
HPAV_FREE_STRUCT_IMPL(mtk_vs_reset_rsp);
HPAV_FREE_STRUCT_IMPL(mtk_vs_get_nvram_cnf);
HPAV_FREE_STRUCT_IMPL(mtk_vs_get_tonemask_cnf);
HPAV_FREE_STRUCT_IMPL(mtk_vs_get_eth_phy_cnf);
HPAV_FREE_STRUCT_IMPL(mtk_vs_eth_stats_cnf);
HPAV_FREE_STRUCT_IMPL(mtk_vs_get_status_cnf);
HPAV_FREE_STRUCT_IMPL(mtk_vs_get_link_stats_cnf);
HPAV_FREE_STRUCT_IMPL(mtk_vs_get_pwm_stats_cnf);
HPAV_FREE_STRUCT_IMPL(mtk_vs_get_pwm_conf_cnf);
HPAV_FREE_STRUCT_IMPL(mtk_vs_set_pwm_conf_cnf);
HPAV_FREE_STRUCT_IMPL(mtk_vs_pwm_generation_cnf);
HPAV_FREE_STRUCT_IMPL(mtk_vs_file_access_cnf);
HPAV_FREE_STRUCT_IMPL(mtk_vs_set_capture_state_cnf);
HPAV_FREE_STRUCT_IMPL(mtk_vs_spi_stats_cnf);
HPAV_FREE_STRUCT_IMPL(mtk_vs_set_tx_cali_cnf);
HPAV_FREE_STRUCT_IMPL(mtk_vs_set_tx_cali_ind);
HPAV_FREE_STRUCT_IMPL(vc_vs_set_sniffer_conf_cnf);
HPAV_FREE_STRUCT_IMPL(vc_vs_set_remote_access_cnf);
HPAV_FREE_STRUCT_IMPL(vc_vs_get_remote_access_cnf);


// Special free
int hpav_free_mtk_vs_get_tonemap_cnf(
    struct hpav_mtk_vs_get_tonemap_cnf *response) {
    struct hpav_mtk_vs_get_tonemap_cnf *response_next;

    while (response != NULL) {
        response_next = response->next;
        free(response->tmi_data);
        free(response->int_data);
        free(response);
        response = response_next;
    }

    return 0;
}

int hpav_free_mtk_vs_get_snr_cnf(struct hpav_mtk_vs_get_snr_cnf *response) {
    struct hpav_mtk_vs_get_snr_cnf *response_next;

    while (response != NULL) {
        response_next = response->next;
        free(response->int_data);
        free(response);
        response = response_next;
    }
    return 0;
}

// HPAV_FREE_STRUCT_IMPL(mtk_vs_get_nw_info_cnf);
int hpav_free_mtk_vs_get_nw_info_cnf(
    struct hpav_mtk_vs_get_nw_info_cnf *response) {
    while (response != NULL) {
        struct hpav_mtk_vs_get_nw_info_cnf *response_next = response->next;
        if (response->num_nws != 0)
            free(response->nwinfo);
        free(response);
        response = response_next;
    }
    return 0;
}

HPAV_SMART_COPY_STRUCT_IMPL(mtk_vs_reset_cnf);
HPAV_SMART_COPY_STRUCT_IMPL(mtk_vs_get_version_cnf);
HPAV_SMART_COPY_STRUCT_IMPL(mtk_vs_get_nw_info_entry);
HPAV_SMART_COPY_STRUCT_IMPL(mtk_vs_get_link_stats_cnf);
HPAV_SMART_COPY_STRUCT_IMPL(mtk_vs_set_tx_cali_cnf);
HPAV_SMART_COPY_STRUCT_IMPL(mtk_vs_set_tx_cali_ind);

HPAV_ENCODE_MTK_MME_IMPL(mtk_vs_set_nvram_req, MMTYPE_MTK_VS_SET_NVRAM_REQ);
HPAV_ENCODE_MTK_MME_IMPL(mtk_vs_get_version_req, MMTYPE_MTK_VS_GET_VERSION_REQ);
HPAV_ENCODE_MTK_MME_IMPL(mtk_vs_reset_req, MMTYPE_MTK_VS_RESET_REQ);
HPAV_ENCODE_MTK_MME_IMPL(mtk_vs_reset_ind, MMTYPE_MTK_VS_RESET_IND);
HPAV_ENCODE_MTK_MME_IMPL(mtk_vs_get_nvram_req, MMTYPE_MTK_VS_GET_NVRAM_REQ);
HPAV_ENCODE_MTK_MME_IMPL(mtk_vs_get_tonemask_req,
                         MMTYPE_MTK_VS_GET_TONEMASK_REQ);
HPAV_ENCODE_MTK_MME_IMPL(mtk_vs_get_eth_phy_req, MMTYPE_MTK_VS_GET_ETH_PHY_REQ);
HPAV_ENCODE_MTK_MME_IMPL(mtk_vs_eth_stats_req, MMTYPE_MTK_VS_ETH_STATS_REQ);
HPAV_ENCODE_MTK_MME_IMPL(mtk_vs_get_status_req, MMTYPE_MTK_VS_GET_STATUS_REQ);
HPAV_ENCODE_MTK_MME_IMPL(mtk_vs_get_tonemap_req, MMTYPE_MTK_VS_GET_TONEMAP_REQ);
HPAV_ENCODE_MTK_MME_IMPL(mtk_vs_set_capture_state_req,
                         MMTYPE_MTK_VS_SET_CAPTURE_STATE_REQ);
HPAV_ENCODE_MTK_MME_IMPL(mtk_vs_get_snr_req, MMTYPE_MTK_VS_GET_SNR_REQ);
HPAV_ENCODE_MTK_MME_IMPL(mtk_vs_get_link_stats_req,
                         MMTYPE_MTK_VS_GET_LINK_STATS_REQ);
HPAV_ENCODE_MTK_MME_IMPL(mtk_vs_get_pwm_stats_req,
                         MMTYPE_MTK_VS_GET_PWM_STATS_REQ);
HPAV_ENCODE_MTK_MME_IMPL(mtk_vs_get_pwm_conf_req,
                         MMTYPE_MTK_VS_GET_PWM_CONF_REQ);
HPAV_ENCODE_MTK_MME_IMPL(mtk_vs_set_pwm_conf_req,
                         MMTYPE_MTK_VS_SET_PWM_CONF_REQ);
HPAV_ENCODE_MTK_MME_IMPL(mtk_vs_pwm_generation_req,
                         MMTYPE_MTK_VS_PWM_GENERATION_REQ);
HPAV_ENCODE_MTK_MME_IMPL(mtk_vs_file_access_req, MMTYPE_MTK_VS_FILE_ACCESS_REQ);
HPAV_ENCODE_MTK_MME_IMPL(mtk_vs_get_nw_info_req, MMTYPE_MTK_VS_GET_NW_INFO_REQ);
HPAV_ENCODE_MTK_MME_IMPL(mtk_vs_spi_stats_req, MMTYPE_MTK_VS_SPI_STATS_REQ);
HPAV_ENCODE_MTK_MME_IMPL(mtk_vs_set_tx_cali_req, MMTYPE_MTK_VS_SET_TX_CALI_REQ);
HPAV_ENCODE_MTK_MME_IMPL(vc_vs_set_sniffer_conf_req,
                         MMTYPE_VC_VS_SET_SNIFFER_CONF_REQ);
HPAV_ENCODE_MTK_MME_IMPL(vc_vs_set_remote_access_req,
                         MMTYPE_VC_VS_SET_REMOTE_ACCESS_REQ);
HPAV_ENCODE_MTK_MME_IMPL(vc_vs_get_remote_access_req,
                         MMTYPE_VC_VS_GET_REMOTE_ACCESS_REQ);

// Special encode

HPAV_DECODE_MTK_MME_IMPL(mtk_vs_set_nvram_cnf);
HPAV_DECODE_MTK_MME_IMPL(mtk_vs_get_version_cnf);
HPAV_DECODE_MTK_MME_IMPL(mtk_vs_reset_cnf);
HPAV_DECODE_MTK_MME_IMPL(mtk_vs_reset_rsp);
HPAV_DECODE_MTK_MME_IMPL(mtk_vs_get_nvram_cnf);
HPAV_DECODE_MTK_MME_IMPL(mtk_vs_get_tonemask_cnf);
HPAV_DECODE_MTK_MME_IMPL(mtk_vs_get_eth_phy_cnf);
HPAV_DECODE_MTK_MME_IMPL(mtk_vs_eth_stats_cnf);
HPAV_DECODE_MTK_MME_IMPL(mtk_vs_get_status_cnf);
HPAV_DECODE_MTK_MME_IMPL(mtk_vs_get_tonemap_cnf);
HPAV_DECODE_MTK_MME_IMPL(mtk_vs_set_capture_state_cnf);
HPAV_DECODE_MTK_MME_IMPL(mtk_vs_get_snr_cnf);
HPAV_DECODE_MTK_MME_IMPL(mtk_vs_get_link_stats_cnf);
HPAV_DECODE_MTK_MME_IMPL(mtk_vs_get_nw_info_cnf);
HPAV_DECODE_MTK_MME_IMPL(mtk_vs_get_pwm_stats_cnf);
HPAV_DECODE_MTK_MME_IMPL(mtk_vs_get_pwm_conf_cnf);
HPAV_DECODE_MTK_MME_IMPL(mtk_vs_set_pwm_conf_cnf);
HPAV_DECODE_MTK_MME_IMPL(mtk_vs_spi_stats_cnf);
HPAV_DECODE_MTK_MME_IMPL(mtk_vs_pwm_generation_cnf);
HPAV_DECODE_MTK_MME_IMPL(mtk_vs_file_access_cnf);
HPAV_DECODE_MTK_MME_IMPL(mtk_vs_set_tx_cali_cnf);
HPAV_DECODE_MTK_MME_IMPL(mtk_vs_set_tx_cali_ind);
HPAV_DECODE_MTK_MME_IMPL(vc_vs_set_sniffer_conf_cnf);
HPAV_DECODE_MTK_MME_IMPL(vc_vs_get_remote_access_cnf);
HPAV_DECODE_MTK_MME_IMPL(vc_vs_set_remote_access_cnf);

HPAV_MME_SNDRCV_IMPL(mtk_vs_set_nvram, req, cnf, MMTYPE_MTK_VS_SET_NVRAM_CNF);
HPAV_MME_SNDRCV_IMPL(mtk_vs_get_version, req, cnf,
                     MMTYPE_MTK_VS_GET_VERSION_CNF);
HPAV_MME_SNDRCV_IMPL(mtk_vs_reset, req, cnf, MMTYPE_MTK_VS_RESET_CNF);
HPAV_MME_SNDRCV_IMPL(mtk_vs_get_nvram, req, cnf, MMTYPE_MTK_VS_GET_NVRAM_CNF);
HPAV_MME_SNDRCV_IMPL(mtk_vs_get_tonemask, req, cnf,
                     MMTYPE_MTK_VS_GET_TONEMASK_CNF);
HPAV_MME_SNDRCV_IMPL(mtk_vs_get_eth_phy, req, cnf,
                     MMTYPE_MTK_VS_GET_ETH_PHY_CNF);
HPAV_MME_SNDRCV_IMPL(mtk_vs_eth_stats, req, cnf, MMTYPE_MTK_VS_ETH_STATS_CNF);
HPAV_MME_SNDRCV_IMPL(mtk_vs_get_status, req, cnf, MMTYPE_MTK_VS_GET_STATUS_CNF);
HPAV_MME_SNDRCV_IMPL(mtk_vs_get_tonemap, req, cnf,
                     MMTYPE_MTK_VS_GET_TONEMAP_CNF);
HPAV_MME_SNDRCV_IMPL(mtk_vs_set_capture_state, req, cnf,
                     MMTYPE_MTK_VS_SET_CAPTURE_STATE_CNF);
HPAV_MME_SNDRCV_IMPL(mtk_vs_get_snr, req, cnf, MMTYPE_MTK_VS_GET_SNR_CNF);
HPAV_MME_SNDRCV_IMPL(mtk_vs_get_link_stats, req, cnf,
                     MMTYPE_MTK_VS_GET_LINK_STATS_CNF);
HPAV_MME_SNDRCV_IMPL(mtk_vs_get_nw_info, req, cnf,
                     MMTYPE_MTK_VS_GET_NW_INFO_CNF);
HPAV_MME_SNDRCV_IMPL(mtk_vs_spi_stats, req, cnf, MMTYPE_MTK_VS_SPI_STATS_CNF);
HPAV_MME_SNDRCV_IMPL(mtk_vs_pwm_generation, req, cnf,
                     MMTYPE_MTK_VS_PWM_GENERATION_CNF);
HPAV_MME_SNDRCV_IMPL(vc_vs_set_sniffer_conf, req, cnf,
                     MMTYPE_VC_VS_SET_SNIFFER_CONF_CNF);
HPAV_MME_SNDRCV_IMPL(vc_vs_set_remote_access, req, cnf,
                     MMTYPE_VC_VS_SET_REMOTE_ACCESS_CNF);
HPAV_MME_SNDRCV_IMPL(vc_vs_get_remote_access, req, cnf,
                     MMTYPE_VC_VS_GET_REMOTE_ACCESS_CNF);

int hpav_mtk_vs_reset_ind_sndrcv(
    struct hpav_chan *channel, unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE],
    struct hpav_mtk_vs_reset_ind *request,
    struct hpav_mtk_vs_reset_rsp **response, unsigned int timeout_ms,
    unsigned int num_fragments, struct hpav_error **error_stack) {
    /* MME packets */
    struct hpav_mme_packet *tx_mme_packets = NULL;
    struct hpav_mme_packet *rx_mme_packets = NULL;
    /* ETH frames */
    struct hpav_eth_frame *tx_frames = NULL;
    struct hpav_eth_frame *current_frame = NULL;
    /* Result */
    int result = -1;
    /* User data passed to pcap_dispatch() callback */
    callback_data_t cb_data;
    /* Hold compiled program */
    struct bpf_program fp;
    /* Timeout management */
    struct hpav_sys_time start_time, end_time;
    /* Init callback user data */
    memset(&cb_data, 0, sizeof(callback_data_t));
    cb_data.type = MMTYPE_MTK_VS_RESET_RSP;
    cb_data.num_fragments = num_fragments;
    /* Source MAC address */
    memcpy(cb_data.src_mac_addr, channel->mac_addr, ETH_MAC_ADDRESS_SIZE);
    /* Destination MAC address */
    memcpy(cb_data.sta_mac_addr, sta_mac_addr, ETH_MAC_ADDRESS_SIZE);
    /* Init response */
    *response = NULL;

    /* Encode the mme into a buffer */
    tx_mme_packets = hpav_encode_mtk_vs_reset_ind(
        cb_data.sta_mac_addr, cb_data.src_mac_addr, request);
    /* Build the frames */
    tx_frames = hpav_build_frames(tx_mme_packets, ETH_FRAME_MIN_SIZE);
    /* TX packets not needed anymore */
    hpav_free_mme_packets(tx_mme_packets);

    /* Compile the program with a filter - non-optimized */
    if (pcap_compile(channel->pcap_chan, &fp, "ether proto 0x88E1", 0, 0) ==
        -1) {
        char buffer[PCAP_ERRBUF_SIZE + 128];
        sprintf(buffer, "PCAP error code : %d, errbuf : %s", result,
                pcap_geterr(channel->pcap_chan));
        hpav_add_error(error_stack, hpav_error_category_network,
                       hpav_error_module_core, HPAV_ERROR_PCAP_ERROR,
                       "pcap_compile failed", buffer);
        return HPAV_ERROR_PCAP_ERROR;
    }

    /* Set the compiled program as the filter */
    if (pcap_setfilter(channel->pcap_chan, &fp) == -1) {
        char buffer[PCAP_ERRBUF_SIZE + 128];
        sprintf(buffer, "PCAP error code : %d, errbuf : %s", result,
                pcap_geterr(channel->pcap_chan));
        hpav_add_error(error_stack, hpav_error_category_network,
                       hpav_error_module_core, HPAV_ERROR_PCAP_ERROR,
                       "pcap_setfilter failed", buffer);
        return HPAV_ERROR_PCAP_ERROR;
    }

    /* Send the frames */
    current_frame = tx_frames;
    while (current_frame != NULL) {
        result =
            pcap_sendpacket(channel->pcap_chan, (unsigned char *)current_frame,
                            current_frame->frame_size);
        if (result != 0) {
            /* PCAP error */
            char buffer[PCAP_ERRBUF_SIZE + 128];
            sprintf(buffer, "PCAP error code : %d, errbuf : %s", result,
                    pcap_geterr(channel->pcap_chan));
            hpav_add_error(error_stack, hpav_error_category_network,
                           hpav_error_module_core, HPAV_ERROR_PCAP_ERROR,
                           "pcap_sendpacket failed", buffer);
            hpav_free_eth_frames(tx_frames);
            return HPAV_ERROR_PCAP_ERROR;
        }
        current_frame = current_frame->next;
    }
    /* TX frames not needed anymore */
    hpav_free_eth_frames(tx_frames);

    /* Receive the frames. If timeout is zero, don't attempt reception. */
    if (timeout_ms > 0) {
        /* Init start time */
        hpav_get_sys_time(&start_time);

        /* We loop until we have collected all the packets with the right
         * Ethertype and MME type */
        do {
            result = pcap_dispatch(channel->pcap_chan, -1, rx_callback,
                                   (u_char *)&cb_data);
            if (result > 0) {
                /* PCAP: number of  packets  processed  on  success */
            } else if (result == 0) {
                /* PCAP: no packets to read */
            } else if (result == -1) {
                /* PCAP: error occured */
                char buffer[PCAP_ERRBUF_SIZE + 128];
                sprintf(buffer, "PCAP error code : %d, errbuf : %s", result,
                        pcap_geterr(channel->pcap_chan));
                hpav_add_error(error_stack, hpav_error_category_network,
                               hpav_error_module_core, HPAV_ERROR_PCAP_ERROR,
                               "pcap_dispatch failed", buffer);
                hpav_free_eth_frames(cb_data.rx_frames);
                return HPAV_ERROR_PCAP_ERROR;
            } else /* (result == -2) */
            {
                /* PCAP: the loop terminated due to a call to pcap_breakloop()
                 * before any packets were  processed */
            }

            /* Compute elapsed time */
            hpav_get_sys_time(&end_time);

            /* Exit loop when caller timeout is reached */
        } while ((hpav_get_elapsed_time_ms(&start_time, &end_time) <=
                  (int)timeout_ms) &&
                 !cb_data.stop);

        /* Defragment frames */
        rx_mme_packets = hpav_defrag_frames(cb_data.rx_frames);
        /* RX Frames not needed anymore */
        hpav_free_eth_frames(cb_data.rx_frames);

        /* Build user level MMEs (MME type specific) */
        *response = hpav_decode_mtk_vs_reset_rsp(rx_mme_packets);

        /* RX MME packets not needed anymore */
        hpav_free_mme_packets(rx_mme_packets);
    }

    return HPAV_OK;
}

int hpav_mtk_vs_get_pwm_stats_sndrcv(
    struct hpav_chan *channel, unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE],
    struct hpav_mtk_vs_get_pwm_stats_req *request,
    struct hpav_mtk_vs_get_pwm_stats_cnf **response, unsigned int timeout_ms,
    unsigned int num_fragments, struct hpav_error **error_stack) {
    /* MME packets */
    struct hpav_mme_packet *tx_mme_packets = NULL;
    struct hpav_mme_packet *rx_mme_packets = NULL;
    /* ETH frames */
    struct hpav_eth_frame *tx_frames = NULL;
    struct hpav_eth_frame *current_frame = NULL;
    /* Result */
    int result = -1;
    /* User data passed to pcap_dispatch() callback */
    callback_data_t cb_data;
    /* Hold compiled program */
    struct bpf_program fp;
    /* Timeout management */
    struct hpav_sys_time start_time, end_time;
    /* Init callback user data */
    memset(&cb_data, 0, sizeof(callback_data_t));
    cb_data.type = MMTYPE_MTK_VS_GET_PWM_STATS_CNF;
    cb_data.num_fragments = num_fragments;
    /* Source MAC address */
    memcpy(cb_data.src_mac_addr, channel->mac_addr, ETH_MAC_ADDRESS_SIZE);
    /* Destination MAC address */
    memcpy(cb_data.sta_mac_addr, sta_mac_addr, ETH_MAC_ADDRESS_SIZE);
    /* Init response */
    *response = NULL;

    /* Encode the mme into a buffer */
    tx_mme_packets = hpav_encode_mtk_vs_get_pwm_stats_req(
        cb_data.sta_mac_addr, cb_data.src_mac_addr, request);
    /* Build the frames */
    tx_frames = hpav_build_frames(tx_mme_packets, ETH_FRAME_MIN_SIZE);
    /* TX packets not needed anymore */
    hpav_free_mme_packets(tx_mme_packets);

    /* Compile the program with a filter - non-optimized */
    if (pcap_compile(channel->pcap_chan, &fp, "ether proto 0x88E1", 0, 0) ==
        -1) {
        char buffer[PCAP_ERRBUF_SIZE + 128];
        sprintf(buffer, "PCAP error code : %d, errbuf : %s", result,
                pcap_geterr(channel->pcap_chan));
        hpav_add_error(error_stack, hpav_error_category_network,
                       hpav_error_module_core, HPAV_ERROR_PCAP_ERROR,
                       "pcap_compile failed", buffer);
        return HPAV_ERROR_PCAP_ERROR;
    }

    /* Set the compiled program as the filter */
    if (pcap_setfilter(channel->pcap_chan, &fp) == -1) {
        char buffer[PCAP_ERRBUF_SIZE + 128];
        sprintf(buffer, "PCAP error code : %d, errbuf : %s", result,
                pcap_geterr(channel->pcap_chan));
        hpav_add_error(error_stack, hpav_error_category_network,
                       hpav_error_module_core, HPAV_ERROR_PCAP_ERROR,
                       "pcap_setfilter failed", buffer);
        return HPAV_ERROR_PCAP_ERROR;
    }

    /* Send the frames */
    current_frame = tx_frames;
    while (current_frame != NULL) {
        result =
            pcap_sendpacket(channel->pcap_chan, (unsigned char *)current_frame,
                            current_frame->frame_size);
        if (result != 0) {
            /* PCAP error */
            char buffer[PCAP_ERRBUF_SIZE + 128];
            sprintf(buffer, "PCAP error code : %d, errbuf : %s", result,
                    pcap_geterr(channel->pcap_chan));
            hpav_add_error(error_stack, hpav_error_category_network,
                           hpav_error_module_core, HPAV_ERROR_PCAP_ERROR,
                           "pcap_sendpacket failed", buffer);
            hpav_free_eth_frames(tx_frames);
            return HPAV_ERROR_PCAP_ERROR;
        }
        current_frame = current_frame->next;
    }
    /* TX frames not needed anymore */
    hpav_free_eth_frames(tx_frames);

    /* Receive the frames. If timeout is zero, don't attempt reception. */
    if (timeout_ms > 0) {
        /* Init start time */
        hpav_get_sys_time(&start_time);

        /* We loop until we have collected all the packets with the right
         * Ethertype and MME type */
        do {
            result = pcap_dispatch(channel->pcap_chan, -1, rx_callback,
                                   (u_char *)&cb_data);
            if (result > 0) {
                /* PCAP: number of  packets  processed  on  success */
                if (cb_data.rx_frames != NULL &&
                    (cb_data.num_fragments_received - 1) == cb_data.fn)
                    break;
            } else if (result == 0) {
                /* PCAP: no packets to read */
            } else if (result == -1) {
                /* PCAP: error occured */
                char buffer[PCAP_ERRBUF_SIZE + 128];
                sprintf(buffer, "PCAP error code : %d, errbuf : %s", result,
                        pcap_geterr(channel->pcap_chan));
                hpav_add_error(error_stack, hpav_error_category_network,
                               hpav_error_module_core, HPAV_ERROR_PCAP_ERROR,
                               "pcap_dispatch failed", buffer);
                hpav_free_eth_frames(cb_data.rx_frames);
                return HPAV_ERROR_PCAP_ERROR;
            } else /* (result == -2) */
            {
                /* PCAP: the loop terminated due to a call to pcap_breakloop()
                 * before any packets were  processed */
            }

            /* Compute elapsed time */
            hpav_get_sys_time(&end_time);

            /* Exit loop when caller timeout is reached */
        } while ((hpav_get_elapsed_time_ms(&start_time, &end_time) <=
                  (int)timeout_ms) &&
                 !cb_data.stop);

        /* Defragment frames */
        rx_mme_packets = hpav_defrag_frames(cb_data.rx_frames);
        /* RX Frames not needed anymore */
        hpav_free_eth_frames(cb_data.rx_frames);
        /* Build user level MMEs (MME type specific) */
        *response = hpav_decode_mtk_vs_get_pwm_stats_cnf(rx_mme_packets);

        /* RX MME packets not needed anymore */
        hpav_free_mme_packets(rx_mme_packets);
    }

    return HPAV_OK;
}

int hpav_mtk_vs_get_pwm_conf_sndrcv(
    struct hpav_chan *channel, unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE],
    struct hpav_mtk_vs_get_pwm_conf_req *request,
    struct hpav_mtk_vs_get_pwm_conf_cnf **response, unsigned int timeout_ms,
    unsigned int num_fragments, struct hpav_error **error_stack) {
    /* MME packets */
    struct hpav_mme_packet *tx_mme_packets = NULL;
    struct hpav_mme_packet *rx_mme_packets = NULL;
    /* ETH frames */
    struct hpav_eth_frame *tx_frames = NULL;
    struct hpav_eth_frame *current_frame = NULL;
    /* Result */
    int result = -1;
    /* User data passed to pcap_dispatch() callback */
    callback_data_t cb_data;
    /* Hold compiled program */
    struct bpf_program fp;
    /* Timeout management */
    struct hpav_sys_time start_time, end_time;
    /* Init callback user data */
    memset(&cb_data, 0, sizeof(callback_data_t));
    cb_data.type = MMTYPE_MTK_VS_GET_PWM_CONF_CNF;
    cb_data.num_fragments = num_fragments;
    /* Source MAC address */
    memcpy(cb_data.src_mac_addr, channel->mac_addr, ETH_MAC_ADDRESS_SIZE);
    /* Destination MAC address */
    memcpy(cb_data.sta_mac_addr, sta_mac_addr, ETH_MAC_ADDRESS_SIZE);
    /* Init response */
    *response = NULL;

    /* Encode the mme into a buffer */
    tx_mme_packets = hpav_encode_mtk_vs_get_pwm_conf_req(
        cb_data.sta_mac_addr, cb_data.src_mac_addr, request);
    /* Build the frames */
    tx_frames = hpav_build_frames(tx_mme_packets, ETH_FRAME_MIN_SIZE);
    /* TX packets not needed anymore */
    hpav_free_mme_packets(tx_mme_packets);

    /* Compile the program with a filter - non-optimized */
    if (pcap_compile(channel->pcap_chan, &fp, "ether proto 0x88E1", 0, 0) ==
        -1) {
        char buffer[PCAP_ERRBUF_SIZE + 128];
        sprintf(buffer, "PCAP error code : %d, errbuf : %s", result,
                pcap_geterr(channel->pcap_chan));
        hpav_add_error(error_stack, hpav_error_category_network,
                       hpav_error_module_core, HPAV_ERROR_PCAP_ERROR,
                       "pcap_compile failed", buffer);
        return HPAV_ERROR_PCAP_ERROR;
    }

    /* Set the compiled program as the filter */
    if (pcap_setfilter(channel->pcap_chan, &fp) == -1) {
        char buffer[PCAP_ERRBUF_SIZE + 128];
        sprintf(buffer, "PCAP error code : %d, errbuf : %s", result,
                pcap_geterr(channel->pcap_chan));
        hpav_add_error(error_stack, hpav_error_category_network,
                       hpav_error_module_core, HPAV_ERROR_PCAP_ERROR,
                       "pcap_setfilter failed", buffer);
        return HPAV_ERROR_PCAP_ERROR;
    }

    /* Send the frames */
    current_frame = tx_frames;
    while (current_frame != NULL) {
        result =
            pcap_sendpacket(channel->pcap_chan, (unsigned char *)current_frame,
                            current_frame->frame_size);
        if (result != 0) {
            /* PCAP error */
            char buffer[PCAP_ERRBUF_SIZE + 128];
            sprintf(buffer, "PCAP error code : %d, errbuf : %s", result,
                    pcap_geterr(channel->pcap_chan));
            hpav_add_error(error_stack, hpav_error_category_network,
                           hpav_error_module_core, HPAV_ERROR_PCAP_ERROR,
                           "pcap_sendpacket failed", buffer);
            hpav_free_eth_frames(tx_frames);
            return HPAV_ERROR_PCAP_ERROR;
        }
        current_frame = current_frame->next;
    }
    /* TX frames not needed anymore */
    hpav_free_eth_frames(tx_frames);

    /* Receive the frames. If timeout is zero, don't attempt reception. */
    if (timeout_ms > 0) {
        /* Init start time */
        hpav_get_sys_time(&start_time);

        /* We loop until we have collected all the packets with the right
         * Ethertype and MME type */
        do {
            result = pcap_dispatch(channel->pcap_chan, -1, rx_callback,
                                   (u_char *)&cb_data);
            if (result > 0) {
                /* PCAP: number of  packets  processed  on  success */
                if (cb_data.rx_frames != NULL &&
                    (cb_data.num_fragments_received - 1) == cb_data.fn)
                    break;
            } else if (result == 0) {
                /* PCAP: no packets to read */
            } else if (result == -1) {
                /* PCAP: error occured */
                char buffer[PCAP_ERRBUF_SIZE + 128];
                sprintf(buffer, "PCAP error code : %d, errbuf : %s", result,
                        pcap_geterr(channel->pcap_chan));
                hpav_add_error(error_stack, hpav_error_category_network,
                               hpav_error_module_core, HPAV_ERROR_PCAP_ERROR,
                               "pcap_dispatch failed", buffer);
                hpav_free_eth_frames(cb_data.rx_frames);
                return HPAV_ERROR_PCAP_ERROR;
            } else /* (result == -2) */
            {
                /* PCAP: the loop terminated due to a call to pcap_breakloop()
                 * before any packets were  processed */
            }

            /* Compute elapsed time */
            hpav_get_sys_time(&end_time);

            /* Exit loop when caller timeout is reached */
        } while ((hpav_get_elapsed_time_ms(&start_time, &end_time) <=
                  (int)timeout_ms) &&
                 !cb_data.stop);

        /* Defragment frames */
        rx_mme_packets = hpav_defrag_frames(cb_data.rx_frames);
        /* RX Frames not needed anymore */
        hpav_free_eth_frames(cb_data.rx_frames);
        /* Build user level MMEs (MME type specific) */
        *response = hpav_decode_mtk_vs_get_pwm_conf_cnf(rx_mme_packets);

        /* RX MME packets not needed anymore */
        hpav_free_mme_packets(rx_mme_packets);
    }

    return HPAV_OK;
}

int hpav_mtk_vs_set_pwm_conf_sndrcv(
    struct hpav_chan *channel, unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE],
    struct hpav_mtk_vs_set_pwm_conf_req *request,
    struct hpav_mtk_vs_set_pwm_conf_cnf **response, unsigned int timeout_ms,
    unsigned int num_fragments, struct hpav_error **error_stack) {
    /* MME packets */
    struct hpav_mme_packet *tx_mme_packets = NULL;
    struct hpav_mme_packet *rx_mme_packets = NULL;
    /* ETH frames */
    struct hpav_eth_frame *tx_frames = NULL;
    struct hpav_eth_frame *current_frame = NULL;
    /* Result */
    int result = -1;
    /* User data passed to pcap_dispatch() callback */
    callback_data_t cb_data;
    /* Hold compiled program */
    struct bpf_program fp;
    /* Timeout management */
    struct hpav_sys_time start_time, end_time;
    /* Init callback user data */
    memset(&cb_data, 0, sizeof(callback_data_t));
    cb_data.type = MMTYPE_MTK_VS_SET_PWM_CONF_CNF;
    cb_data.num_fragments = num_fragments;
    /* Source MAC address */
    memcpy(cb_data.src_mac_addr, channel->mac_addr, ETH_MAC_ADDRESS_SIZE);
    /* Destination MAC address */
    memcpy(cb_data.sta_mac_addr, sta_mac_addr, ETH_MAC_ADDRESS_SIZE);
    /* Init response */
    *response = NULL;

    /* Encode the mme into a buffer */
    tx_mme_packets = hpav_encode_mtk_vs_set_pwm_conf_req(
        cb_data.sta_mac_addr, cb_data.src_mac_addr, request);
    /* Build the frames */
    tx_frames = hpav_build_frames(tx_mme_packets, ETH_FRAME_MIN_SIZE);
    /* TX packets not needed anymore */
    hpav_free_mme_packets(tx_mme_packets);

    /* Compile the program with a filter - non-optimized */
    if (pcap_compile(channel->pcap_chan, &fp, "ether proto 0x88E1", 0, 0) ==
        -1) {
        char buffer[PCAP_ERRBUF_SIZE + 128];
        sprintf(buffer, "PCAP error code : %d, errbuf : %s", result,
                pcap_geterr(channel->pcap_chan));
        hpav_add_error(error_stack, hpav_error_category_network,
                       hpav_error_module_core, HPAV_ERROR_PCAP_ERROR,
                       "pcap_compile failed", buffer);
        return HPAV_ERROR_PCAP_ERROR;
    }

    /* Set the compiled program as the filter */
    if (pcap_setfilter(channel->pcap_chan, &fp) == -1) {
        char buffer[PCAP_ERRBUF_SIZE + 128];
        sprintf(buffer, "PCAP error code : %d, errbuf : %s", result,
                pcap_geterr(channel->pcap_chan));
        hpav_add_error(error_stack, hpav_error_category_network,
                       hpav_error_module_core, HPAV_ERROR_PCAP_ERROR,
                       "pcap_setfilter failed", buffer);
        return HPAV_ERROR_PCAP_ERROR;
    }

    /* Send the frames */
    current_frame = tx_frames;
    while (current_frame != NULL) {
        result =
            pcap_sendpacket(channel->pcap_chan, (unsigned char *)current_frame,
                            current_frame->frame_size);
        if (result != 0) {
            /* PCAP error */
            char buffer[PCAP_ERRBUF_SIZE + 128];
            sprintf(buffer, "PCAP error code : %d, errbuf : %s", result,
                    pcap_geterr(channel->pcap_chan));
            hpav_add_error(error_stack, hpav_error_category_network,
                           hpav_error_module_core, HPAV_ERROR_PCAP_ERROR,
                           "pcap_sendpacket failed", buffer);
            hpav_free_eth_frames(tx_frames);
            return HPAV_ERROR_PCAP_ERROR;
        }
        current_frame = current_frame->next;
    }
    /* TX frames not needed anymore */
    hpav_free_eth_frames(tx_frames);

    /* Receive the frames. If timeout is zero, don't attempt reception. */
    if (timeout_ms > 0) {
        /* Init start time */
        hpav_get_sys_time(&start_time);

        /* We loop until we have collected all the packets with the right
         * Ethertype and MME type */
        do {
            result = pcap_dispatch(channel->pcap_chan, -1, rx_callback,
                                   (u_char *)&cb_data);
            if (result > 0) {
                /* PCAP: number of  packets  processed  on  success */
                if (cb_data.rx_frames != NULL &&
                    (cb_data.num_fragments_received - 1) == cb_data.fn)
                    break;
            } else if (result == 0) {
                /* PCAP: no packets to read */
            } else if (result == -1) {
                /* PCAP: error occured */
                char buffer[PCAP_ERRBUF_SIZE + 128];
                sprintf(buffer, "PCAP error code : %d, errbuf : %s", result,
                        pcap_geterr(channel->pcap_chan));
                hpav_add_error(error_stack, hpav_error_category_network,
                               hpav_error_module_core, HPAV_ERROR_PCAP_ERROR,
                               "pcap_dispatch failed", buffer);
                hpav_free_eth_frames(cb_data.rx_frames);
                return HPAV_ERROR_PCAP_ERROR;
            } else /* (result == -2) */
            {
                /* PCAP: the loop terminated due to a call to pcap_breakloop()
                 * before any packets were  processed */
            }

            /* Compute elapsed time */
            hpav_get_sys_time(&end_time);

            /* Exit loop when caller timeout is reached */
        } while ((hpav_get_elapsed_time_ms(&start_time, &end_time) <=
                  (int)timeout_ms) &&
                 !cb_data.stop);

        /* Defragment frames */
        rx_mme_packets = hpav_defrag_frames(cb_data.rx_frames);
        /* RX Frames not needed anymore */
        hpav_free_eth_frames(cb_data.rx_frames);
        /* Build user level MMEs (MME type specific) */
        *response = hpav_decode_mtk_vs_set_pwm_conf_cnf(rx_mme_packets);

        /* RX MME packets not needed anymore */
        hpav_free_mme_packets(rx_mme_packets);
    }

    return HPAV_OK;
}

int hpav_mtk_vs_set_tx_cali_sndrcv(
    struct hpav_chan *channel, unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE],
    struct hpav_mtk_vs_set_tx_cali_req *request,
    struct hpav_mtk_vs_set_tx_cali_cnf **response, unsigned int timeout_ms,
    unsigned int num_fragments, struct hpav_error **error_stack) {
    /* MME packets */
    struct hpav_mme_packet *tx_mme_packets = NULL;
    struct hpav_mme_packet *rx_mme_packets = NULL;
    /* ETH frames */
    struct hpav_eth_frame *tx_frames = NULL;
    struct hpav_eth_frame *current_frame = NULL;
    /* Result */
    int result = -1;
    /* User data passed to pcap_dispatch() callback */
    callback_data_t cb_data;
    /* Hold compiled program */
    struct bpf_program fp;
    /* Timeout management */
    struct hpav_sys_time start_time, end_time;
    /* Init callback user data */
    memset(&cb_data, 0, sizeof(callback_data_t));
    cb_data.type = MMTYPE_MTK_VS_SET_TX_CALI_CNF;
    /* Source MAC address */
    memcpy(cb_data.src_mac_addr, channel->mac_addr, ETH_MAC_ADDRESS_SIZE);
    /* Destination MAC address */
    memcpy(cb_data.sta_mac_addr, sta_mac_addr, ETH_MAC_ADDRESS_SIZE);
    /* Init response */
    *response = NULL;

    /* Encode the mme into a buffer */
    tx_mme_packets = hpav_encode_mtk_vs_set_tx_cali_req(
        cb_data.sta_mac_addr, cb_data.src_mac_addr, request);
    /* Build the frames */
    tx_frames = hpav_build_frames(tx_mme_packets, ETH_FRAME_MIN_SIZE);
    /* TX packets not needed anymore */
    hpav_free_mme_packets(tx_mme_packets);

    /* Compile the program with a filter - non-optimized */
    if (pcap_compile(channel->pcap_chan, &fp, "ether proto 0x88E1", 0, 0) ==
        -1) {
        char buffer[PCAP_ERRBUF_SIZE + 128];
        sprintf(buffer, "PCAP error code : %d, errbuf : %s", result,
                pcap_geterr(channel->pcap_chan));
        hpav_add_error(error_stack, hpav_error_category_network,
                       hpav_error_module_core, HPAV_ERROR_PCAP_ERROR,
                       "pcap_compile failed", buffer);
        return HPAV_ERROR_PCAP_ERROR;
    }

    /* Set the compiled program as the filter */
    if (pcap_setfilter(channel->pcap_chan, &fp) == -1) {
        char buffer[PCAP_ERRBUF_SIZE + 128];
        sprintf(buffer, "PCAP error code : %d, errbuf : %s", result,
                pcap_geterr(channel->pcap_chan));
        hpav_add_error(error_stack, hpav_error_category_network,
                       hpav_error_module_core, HPAV_ERROR_PCAP_ERROR,
                       "pcap_setfilter failed", buffer);
        return HPAV_ERROR_PCAP_ERROR;
    }

    /* Send the frames */
    current_frame = tx_frames;
    while (current_frame != NULL) {
        result =
            pcap_sendpacket(channel->pcap_chan, (unsigned char *)current_frame,
                            current_frame->frame_size);
        if (result != 0) {
            /* PCAP error */
            char buffer[PCAP_ERRBUF_SIZE + 128];
            sprintf(buffer, "PCAP error code : %d, errbuf : %s", result,
                    pcap_geterr(channel->pcap_chan));
            hpav_add_error(error_stack, hpav_error_category_network,
                           hpav_error_module_core, HPAV_ERROR_PCAP_ERROR,
                           "pcap_sendpacket failed", buffer);
            hpav_free_eth_frames(tx_frames);
            return HPAV_ERROR_PCAP_ERROR;
        }
        current_frame = current_frame->next;
    }
    /* TX frames not needed anymore */
    hpav_free_eth_frames(tx_frames);

    /* Receive the frames. If timeout is zero, don't attempt reception. */
    if (timeout_ms > 0) {
        /* Init start time */
        hpav_get_sys_time(&start_time);

        /* We loop until we have collected all the packets with the right
         * Ethertype and MME type */
        do {
            result = pcap_dispatch(channel->pcap_chan, -1, rx_callback,
                                   (u_char *)&cb_data);
            if (result > 0) {
                /* PCAP: number of  packets  processed  on  success */
                if (cb_data.rx_frames != NULL &&
                    (cb_data.num_fragments_received - 1) == cb_data.fn)
                    break;
            } else if (result == 0) {
                /* PCAP: no packets to read */
            } else if (result == -1) {
                /* PCAP: error occured */
                char buffer[PCAP_ERRBUF_SIZE + 128];
                sprintf(buffer, "PCAP error code : %d, errbuf : %s", result,
                        pcap_geterr(channel->pcap_chan));
                hpav_add_error(error_stack, hpav_error_category_network,
                               hpav_error_module_core, HPAV_ERROR_PCAP_ERROR,
                               "pcap_dispatch failed", buffer);
                hpav_free_eth_frames(cb_data.rx_frames);
                return HPAV_ERROR_PCAP_ERROR;
            } else /* (result == -2) */
            {
                /* PCAP: the loop terminated due to a call to pcap_breakloop()
                 * before any packets were  processed */
            }

            /* Compute elapsed time */
            hpav_get_sys_time(&end_time);

            /* Exit loop when caller timeout is reached */
        } while ((hpav_get_elapsed_time_ms(&start_time, &end_time) <=
                  (int)timeout_ms) &&
                 !cb_data.stop);

        /* Defragment frames */
        rx_mme_packets = hpav_defrag_frames(cb_data.rx_frames);
        /* RX Frames not needed anymore */
        hpav_free_eth_frames(cb_data.rx_frames);
        /* Build user level MMEs (MME type specific) */
        *response = hpav_decode_mtk_vs_set_tx_cali_cnf(rx_mme_packets);

        /* RX MME packets not needed anymore */
        hpav_free_mme_packets(rx_mme_packets);
    }

    return HPAV_OK;
}

int hpav_mtk_vs_set_tx_cali_ind_rcv(
    struct hpav_chan *channel, struct hpav_mtk_vs_set_tx_cali_ind **response,
    unsigned int timeout_ms, unsigned int num_fragments,
    struct hpav_error **error_stack) {
    /* MME packets */
    struct hpav_mme_packet *rx_mme_packets = NULL;

    /* Result */
    int result = -1;
    /* User data passed to pcap_dispatch() callback */
    callback_data_t cb_data;
    /* Hold compiled program */
    struct bpf_program fp;
    /* Timeout management */
    struct hpav_sys_time start_time, end_time;
    /* Init callback user data */
    memset(&cb_data, 0, sizeof(callback_data_t));
    cb_data.type = MMTYPE_MTK_VS_SET_TX_CALI_IND;
    /* Source MAC address */
    memcpy(cb_data.src_mac_addr, channel->mac_addr, ETH_MAC_ADDRESS_SIZE);
    /* Init response */
    *response = NULL;

    /* Compile the program with a filter - non-optimized */
    if (pcap_compile(channel->pcap_chan, &fp, "ether proto 0x88E1", 0, 0) ==
        -1) {
        char buffer[PCAP_ERRBUF_SIZE + 128];
        sprintf(buffer, "PCAP error code : %d, errbuf : %s", result,
                pcap_geterr(channel->pcap_chan));
        hpav_add_error(error_stack, hpav_error_category_network,
                       hpav_error_module_core, HPAV_ERROR_PCAP_ERROR,
                       "pcap_compile failed", buffer);
        return HPAV_ERROR_PCAP_ERROR;
    }

    /* Set the compiled program as the filter */
    if (pcap_setfilter(channel->pcap_chan, &fp) == -1) {
        char buffer[PCAP_ERRBUF_SIZE + 128];
        sprintf(buffer, "PCAP error code : %d, errbuf : %s", result,
                pcap_geterr(channel->pcap_chan));
        hpav_add_error(error_stack, hpav_error_category_network,
                       hpav_error_module_core, HPAV_ERROR_PCAP_ERROR,
                       "pcap_setfilter failed", buffer);
        return HPAV_ERROR_PCAP_ERROR;
    }

    /* Receive the frames. If timeout is zero, don't attempt reception. */
    if (timeout_ms > 0) {
        /* Init start time */
        hpav_get_sys_time(&start_time);

        /* We loop until we have collected all the packets with the right
         * Ethertype and MME type */
        do {
            result = pcap_dispatch(channel->pcap_chan, -1, rx_callback,
                                   (u_char *)&cb_data);
            if (result > 0) {
                /* PCAP: number of  packets  processed  on  success */
                if (cb_data.rx_frames != NULL &&
                    (cb_data.num_fragments_received - 1) == cb_data.fn)
                    break;
            } else if (result == 0) {
                /* PCAP: no packets to read */
            } else if (result == -1) {
                /* PCAP: error occured */
                char buffer[PCAP_ERRBUF_SIZE + 128];
                sprintf(buffer, "PCAP error code : %d, errbuf : %s", result,
                        pcap_geterr(channel->pcap_chan));
                hpav_add_error(error_stack, hpav_error_category_network,
                               hpav_error_module_core, HPAV_ERROR_PCAP_ERROR,
                               "pcap_dispatch failed", buffer);
                hpav_free_eth_frames(cb_data.rx_frames);
                return HPAV_ERROR_PCAP_ERROR;
            } else /* (result == -2) */
            {
                /* PCAP: the loop terminated due to a call to pcap_breakloop()
                 * before any packets were  processed */
            }

            /* Compute elapsed time */
            hpav_get_sys_time(&end_time);

            /* Exit loop when caller timeout is reached */
        } while ((hpav_get_elapsed_time_ms(&start_time, &end_time) <=
                  (int)timeout_ms) &&
                 !cb_data.stop);

        /* Defragment frames */
        rx_mme_packets = hpav_defrag_frames(cb_data.rx_frames);
        /* RX Frames not needed anymore */
        hpav_free_eth_frames(cb_data.rx_frames);
        /* Build user level MMEs (MME type specific) */
        *response = hpav_decode_mtk_vs_set_tx_cali_ind(rx_mme_packets);

        /* RX MME packets not needed anymore */
        hpav_free_mme_packets(rx_mme_packets);
    }

    return HPAV_OK;
}

int hpav_mtk_vs_file_access_sndrcv(
    struct hpav_chan *channel, unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE],
    struct hpav_mtk_vs_file_access_req *request,
    struct hpav_mtk_vs_file_access_cnf **response, unsigned int timeout_ms,
    unsigned int num_fragments, struct hpav_error **error_stack,
    unsigned char scan) {
    /* MME packets */
    struct hpav_mme_packet *tx_mme_packets = NULL;
    struct hpav_mme_packet *rx_mme_packets = NULL;
    /* ETH frames */
    struct hpav_eth_frame *tx_frames = NULL;
    struct hpav_eth_frame *current_frame = NULL;
    /* Result */
    int result = -1;
    /* User data passed to pcap_dispatch() callback */
    callback_data_t cb_data;
    /* Hold compiled program */
    struct bpf_program fp;
    /* Timeout management */
    struct hpav_sys_time start_time, end_time;
    /* Init callback user data */
    memset(&cb_data, 0, sizeof(callback_data_t));
    cb_data.type = MMTYPE_MTK_VS_FILE_ACCESS_CNF;
    cb_data.num_fragments = num_fragments;
    /* Source MAC address */
    memcpy(cb_data.src_mac_addr, channel->mac_addr, ETH_MAC_ADDRESS_SIZE);
    /* Destination MAC address */
    memcpy(cb_data.sta_mac_addr, sta_mac_addr, ETH_MAC_ADDRESS_SIZE);

    /* Init response */
    *response = NULL;

    /* Encode the mme into a buffer */
    tx_mme_packets = hpav_encode_mtk_vs_file_access_req(
        cb_data.sta_mac_addr, cb_data.src_mac_addr, request);
    /* Build the frames */
    tx_frames = hpav_build_frames(tx_mme_packets, ETH_FRAME_MIN_SIZE);
    /* TX packets not needed anymore */
    hpav_free_mme_packets(tx_mme_packets);

    /* Compile the program with a filter - non-optimized */
    if (pcap_compile(channel->pcap_chan, &fp, "ether proto 0x88E1", 0, 0) ==
        -1) {
        char buffer[PCAP_ERRBUF_SIZE + 128];
        sprintf(buffer, "PCAP error code : %d, errbuf : %s", result,
                pcap_geterr(channel->pcap_chan));
        hpav_add_error(error_stack, hpav_error_category_network,
                       hpav_error_module_core, HPAV_ERROR_PCAP_ERROR,
                       "pcap_compile failed", buffer);
        return HPAV_ERROR_PCAP_ERROR;
    }

    /* Set the compiled program as the filter */
    if (pcap_setfilter(channel->pcap_chan, &fp) == -1) {
        char buffer[PCAP_ERRBUF_SIZE + 128];
        sprintf(buffer, "PCAP error code : %d, errbuf : %s", result,
                pcap_geterr(channel->pcap_chan));
        hpav_add_error(error_stack, hpav_error_category_network,
                       hpav_error_module_core, HPAV_ERROR_PCAP_ERROR,
                       "pcap_setfilter failed", buffer);
        return HPAV_ERROR_PCAP_ERROR;
    }

    /* Send the frames */
    current_frame = tx_frames;
    while (current_frame != NULL) {
        result =
            pcap_sendpacket(channel->pcap_chan, (unsigned char *)current_frame,
                            current_frame->frame_size);
        if (result != 0) {
            /* PCAP error */
            char buffer[PCAP_ERRBUF_SIZE + 128];
            sprintf(buffer, "PCAP error code : %d, errbuf : %s", result,
                    pcap_geterr(channel->pcap_chan));
            hpav_add_error(error_stack, hpav_error_category_network,
                           hpav_error_module_core, HPAV_ERROR_PCAP_ERROR,
                           "pcap_sendpacket failed", buffer);
            hpav_free_eth_frames(tx_frames);
            return HPAV_ERROR_PCAP_ERROR;
        }
        current_frame = current_frame->next;
    }
    /* TX frames not needed anymore */
    hpav_free_eth_frames(tx_frames);

    /* Receive the frames. If timeout is zero, don't attempt reception. */
    if (timeout_ms > 0) {
        /* Init start time */
        hpav_get_sys_time(&start_time);

        /* We loop until we have collected all the packets with the right
         * Ethertype and MME type */
        do {
            result = pcap_dispatch(channel->pcap_chan, -1, rx_callback,
                                   (u_char *)&cb_data);
            if (result > 0) {
                /* PCAP: number of  packets  processed  on  success */
                if (scan == 0 && cb_data.num_fragments_received > 0)
                    break;
            } else if (result == 0) {
                /* PCAP: no packets to read */
            } else if (result == -1) {
                /* PCAP: error occured */
                char buffer[PCAP_ERRBUF_SIZE + 128];
                sprintf(buffer, "PCAP error code : %d, errbuf : %s", result,
                        pcap_geterr(channel->pcap_chan));
                hpav_add_error(error_stack, hpav_error_category_network,
                               hpav_error_module_core, HPAV_ERROR_PCAP_ERROR,
                               "pcap_dispatch failed", buffer);
                hpav_free_eth_frames(cb_data.rx_frames);
                return HPAV_ERROR_PCAP_ERROR;
            } else /* (result == -2) */
            {
                /* PCAP: the loop terminated due to a call to pcap_breakloop()
                 * before any packets were  processed */
            }

            /* Compute elapsed time */
            hpav_get_sys_time(&end_time);

            /* Exit loop when caller timeout is reached */
        } while ((hpav_get_elapsed_time_ms(&start_time, &end_time) <=
                  (int)timeout_ms) &&
                 !cb_data.stop);

        /* Defragment frames */
        rx_mme_packets = hpav_defrag_frames(cb_data.rx_frames);
        /* RX Frames not needed anymore */
        hpav_free_eth_frames(cb_data.rx_frames);

        /* Build user level MMEs (MME type specific) */
        *response = hpav_decode_mtk_vs_file_access_cnf(rx_mme_packets);

        /* RX MME packets not needed anymore */
        hpav_free_mme_packets(rx_mme_packets);
    }

    return HPAV_OK;
}

// Prepare a header for a Mstar MME
int hpav_setup_mtk_mme_header(unsigned short mme_type,
                              unsigned int num_fragments,
                              unsigned int fragment_num,
                              unsigned fragment_sequence_number,
                              struct hpav_mtk_mme_header *header) {
    header->mmv = MME_HEADER_MMV_HPAV11;
    header->mmtype = mme_type;
    header->fmi_nf_fn = ((num_fragments << MME_HEADER_NUM_FRAGMENTS_SHIFT) &
                         MME_HEADER_NUM_FRAGMENTS_MASK) |
                        ((fragment_num << MME_HEADER_FRAGMENT_NUMBER_SHIFT) &
                         MME_HEADER_FRAGMENT_NUMBER_MASK);
    header->fmi_fmsn = fragment_sequence_number;
    header->oui[0] = 0x00;
    header->oui[1] = 0x13;
    header->oui[2] = 0xD7;
    return 0;
}

// Send a raw Mstar MME on the channel
// Caller prepares the MME header
int hpav_send_raw_mtk_mme(struct hpav_chan *channel,
                          unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE],
                          struct hpav_mtk_mme_header *header,
                          unsigned char *mme_data, unsigned int mme_data_size) {
    unsigned char *new_mme = NULL;
    unsigned int mme_size = sizeof(struct hpav_mtk_mme_header) + mme_data_size;
    struct hpav_mme_packet *new_packet =
        (struct hpav_mme_packet *)malloc(sizeof(struct hpav_mme_packet));
    struct hpav_mtk_mme_frame *mme_frame = NULL;
    struct hpav_eth_frame *tx_frames = NULL;
    struct hpav_eth_frame *current_frame = NULL;
    int result = -1;

    // First build a MME packet to feed common function calls
    new_mme = (unsigned char *)malloc(mme_size);
    mme_frame = (struct hpav_mtk_mme_frame *)new_mme;
    memcpy(&mme_frame->header, header, sizeof(struct hpav_mtk_mme_header));
    memcpy(&mme_frame->unknown_mtk_mme, mme_data, mme_data_size);
    // Byte ordering issues should be resolved by the caller
    new_packet->data_size = mme_size;
    new_packet->data = new_mme;
    memcpy(new_packet->dst_mac_addr, sta_mac_addr, ETH_MAC_ADDRESS_SIZE);
    memcpy(new_packet->src_mac_addr, channel->mac_addr, ETH_MAC_ADDRESS_SIZE);
    new_packet->next = NULL;

    // Build ETH frames (eventually this will allow sending fragmented MMEs
    tx_frames = hpav_build_frames(new_packet, ETH_FRAME_MIN_SIZE);

    current_frame = tx_frames;
    while (current_frame != NULL) {
        result =
            pcap_sendpacket(channel->pcap_chan, (unsigned char *)current_frame,
                            current_frame->frame_size);
        if (result != 0) {
            /* Here add exit if something wrong occured */
        }
        current_frame = current_frame->next;
    }

    return result;
}
