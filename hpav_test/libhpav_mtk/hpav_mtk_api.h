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
#ifndef __HPAV_MTK_API_H__
#define __HPAV_MTK_API_H__

/* ??? (PP) Check that */
#if !defined(_WIN32)
#include <sys/types.h>

#if !defined(u_int64)
#define u_int64 u_int64_t
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_MSC_VER) || defined(SWIGCSHARP)
#define __packed
#define __packed_end
#pragma pack(push, hpav, 1)
#else
#define __packed
#define __packed_end __attribute__((packed))
#endif

#define ENABLE_RLE 1
#define MTK_POSSIBLE_CARRIERS_MAX HPAV_POSSIBLE_CARRIERS_MAX
#define MTK_TONEMASK_SIZE MTK_POSSIBLE_CARRIERS_MAX / 8
#define MTK_MODULATION_LIST_MAX_SIZE (MTK_POSSIBLE_CARRIERS_MAX / 2)
#define MTK_SNR_LIST_MAX_SIZE (MTK_POSSIBLE_CARRIERS_MAX / 4)
#define MTK_SPECTRUM_SIZE (MTK_POSSIBLE_CARRIERS_MAX / 4)
#define MTK_AMP_MAP_MAX_SIZE (MTK_POSSIBLE_CARRIERS_MAX / 4)
#define PORT_NB 5
#define SERVICE_PARAMETERS_NB 7

// Mstar specific macros and API
#define MAX_MOD_COUNT 9

// Mstar vendor specific MMTYPES
#define MMTYPE_MTK_VS_GET_VERSION_REQ 0xA000
#define MMTYPE_MTK_VS_GET_VERSION_CNF 0xA001

#define MMTYPE_MTK_VS_RESET_REQ 0xA008
#define MMTYPE_MTK_VS_RESET_CNF 0xA009
#define MMTYPE_MTK_VS_RESET_IND 0xA00A
#define MMTYPE_MTK_VS_RESET_RSP 0xA00B

#define MMTYPE_MTK_VS_GET_TONEMASK_REQ 0xA01C
#define MMTYPE_MTK_VS_GET_TONEMASK_CNF 0xA01D

#define MMTYPE_MTK_VS_GET_ETH_PHY_REQ 0xA020
#define MMTYPE_MTK_VS_GET_ETH_PHY_CNF 0xA021

#define MMTYPE_MTK_VS_ETH_STATS_REQ 0xA024
#define MMTYPE_MTK_VS_ETH_STATS_CNF 0xA025

#define MMTYPE_MTK_VS_GET_STATUS_REQ 0xA030
#define MMTYPE_MTK_VS_GET_STATUS_CNF 0xA031

#define MMTYPE_MTK_VS_GET_TONEMAP_REQ 0xA034
#define MMTYPE_MTK_VS_GET_TONEMAP_CNF 0xA035

#define MMTYPE_MTK_VS_SET_CAPTURE_STATE_REQ 0xA100
#define MMTYPE_MTK_VS_SET_CAPTURE_STATE_CNF 0xA101

#define MMTYPE_MTK_VS_GET_SNR_REQ 0xA038
#define MMTYPE_MTK_VS_GET_SNR_CNF 0xA039

#define MMTYPE_MTK_VS_GET_LINK_STATS_REQ 0xA040
#define MMTYPE_MTK_VS_GET_LINK_STATS_CNF 0xA041

#define MMTYPE_MTK_VS_SET_NVRAM_REQ 0xA104
#define MMTYPE_MTK_VS_SET_NVRAM_CNF 0xA105

#define MMTYPE_MTK_VS_GET_NVRAM_REQ 0xA108
#define MMTYPE_MTK_VS_GET_NVRAM_CNF 0xA109

#define MMTYPE_MTK_VS_GET_PWM_STATS_REQ 0xA10C
#define MMTYPE_MTK_VS_GET_PWM_STATS_CNF 0xA10D

#define MMTYPE_MTK_VS_GET_PWM_CONF_REQ 0xA110
#define MMTYPE_MTK_VS_GET_PWM_CONF_CNF 0xA111

#define MMTYPE_MTK_VS_SET_PWM_CONF_REQ 0xA114
#define MMTYPE_MTK_VS_SET_PWM_CONF_CNF 0xA115

#define MMTYPE_MTK_VS_PWM_GENERATION_REQ 0xA118
#define MMTYPE_MTK_VS_PWM_GENERATION_CNF 0xA119

#define MMTYPE_MTK_VS_SPI_STATS_REQ 0xA11C
#define MMTYPE_MTK_VS_SPI_STATS_CNF 0xA11D

#define MMTYPE_MTK_VS_FILE_ACCESS_REQ 0xA4FC
#define MMTYPE_MTK_VS_FILE_ACCESS_CNF 0xA4FD


#define MMTYPE_MTK_VS_GET_NW_INFO_REQ 0xA0FC
#define MMTYPE_MTK_VS_GET_NW_INFO_CNF 0xA0FD

#define MMTYPE_MTK_VS_SET_TX_CALI_REQ 0xA128
#define MMTYPE_MTK_VS_SET_TX_CALI_CNF 0xA129
#define MMTYPE_MTK_VS_SET_TX_CALI_IND 0xA12A

#define MMTYPE_VC_VS_SET_SNIFFER_CONF_REQ 0xA138
#define MMTYPE_VC_VS_SET_SNIFFER_CONF_CNF 0xA139

#define MMTYPE_VC_VS_SET_REMOTE_ACCESS_REQ 0xA13C
#define MMTYPE_VC_VS_SET_REMOTE_ACCESS_CNF 0xA13D
#define MMTYPE_VC_VS_GET_REMOTE_ACCESS_REQ 0xA140
#define MMTYPE_VC_VS_GET_REMOTE_ACCESS_CNF 0xA141
// Data structures
/***
 * Mstar manufacturer specific
 ***/

// VS_SET_NVRAM.REQ
#define MTK_NVRAM_BLOCK_SIZE 1024
struct __packed hpav_mtk_vs_set_nvram_req {
    // NVRAM 1024kB block index
    unsigned char block_index;
    // NVRAM data total size
    unsigned short nvram_size;
    // NVRAM data's checksum
    unsigned int checksum;
    // NVRAM data
    unsigned char data[MTK_NVRAM_BLOCK_SIZE];
} __packed_end;

// VS_SET_NVRAM.CNF
struct __packed hpav_mtk_vs_set_nvram_cnf {
    // Result
    unsigned char result;
    // Address of STA responding
    unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE];
    // Chain mmes when receiving more than one
    struct hpav_mtk_vs_set_nvram_cnf *next;
} __packed_end;

/***
 * Mstar vendor specific
 ***/

// VS_GET_VERSION.REQ
struct __packed hpav_mtk_vs_get_version_req {
    // This MME has no content. Padding to please C.
    int padding;
} __packed_end;

// VS_GET_VERSION.CNF
struct __packed hpav_mtk_vs_get_version_cnf {
    // Result
    unsigned char result;
    // Device ID
    unsigned short device_id;
    // Current image index
    unsigned char image_index;
    // Current application layer version (always NULL terminated)
    char applicative_version[16];
    // Current AV stack version (always NULL terminated)
    char av_stack_version[64];
    // Alternate applicative version (always NULL terminated)
    char alternate_applicative_version[16];
    // Bootloader version
    char bootloader_version[64];
    // Address of STA responding
    unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE];
    // Chain mmes when receiving more than one
    struct hpav_mtk_vs_get_version_cnf *next;
} __packed_end;

// VS_RESET.REQ
struct __packed hpav_mtk_vs_reset_req {
    // This MME has no content. Padding to please C.
    int padding;
} __packed_end;

// VS_RESET.CNF
struct __packed hpav_mtk_vs_reset_cnf {
    // Result
    unsigned char result;
    // Address of STA responding
    unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE];
    // Chain mmes when receiving more than one
    struct hpav_mtk_vs_reset_cnf *next;
} __packed_end;

// VS_RESET.IND
struct __packed hpav_mtk_vs_reset_ind {
    // This MME has no content; padding to please C
    int padding;
} __packed_end;

// VS_RESET.RSP
struct __packed hpav_mtk_vs_reset_rsp {
    // Address of STA responding
    unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE];
    // Chain MMEs when receiving more than one
    struct hpav_mtk_vs_reset_rsp *next;
} __packed_end;

// VS_GET_NVRAM.REQ
struct __packed hpav_mtk_vs_get_nvram_req {
    // NVRAM 1024 bytes block index
    unsigned char index;
} __packed_end;

// VS_GET_NVRAM.CNF
struct __packed hpav_mtk_vs_get_nvram_cnf {
    // Result
    unsigned char result;
    // Requested NVRAM 1024 bytes block index
    unsigned char index;
    // NVRAM size in the flash
    unsigned short nvram_size;
    // NVRAM block data of 1024 bytes
    unsigned char data[1024];
    // Address of STA responding
    unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE];
    // Chain mmes when receiving more than one
    struct hpav_mtk_vs_get_nvram_cnf *next;
} __packed_end;

// VS_GET_TONEMASK.REQ
struct __packed hpav_mtk_vs_get_tonemask_req {
    // Address of STA responding
    unsigned char peer_mac_addr[ETH_MAC_ADDRESS_SIZE];
} __packed_end;

// VS_GET_TONEMASK.CNF
struct __packed hpav_mtk_vs_get_tonemask_cnf {
    // Result
    unsigned char result;
    // Tonemask bitfield for the 1536 carriers from 0 MHz to 37.5 MHz
    unsigned char tonemask[MTK_TONEMASK_SIZE];
    // Address of STA responding
    unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE];
    // Chain mmes when receiving more than one
    struct hpav_mtk_vs_get_tonemask_cnf *next;
} __packed_end;

// VS_GET_ETH_PHY.REQ
struct __packed hpav_mtk_vs_get_eth_phy_req {
    // This MME has no content. Padding to please C.
    int padding;
} __packed_end;

// VS_GET_ETH_PHY.CNF
struct __packed hpav_mtk_vs_get_eth_phy_cnf {
    // Result
    unsigned char result;
    // Link status
    unsigned char link;
    // Speed
    unsigned char speed;
    // Duplex
    unsigned char duplex;
    // PHY address
    unsigned char phy_addr;
    // Address of STA responding
    unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE];
    // Chain mmes when receiving more than one
    struct hpav_mtk_vs_get_eth_phy_cnf *next;
} __packed_end;

// VS_ETH_STATS.REQ
struct __packed hpav_mtk_vs_eth_stats_req {
    // Command.
    unsigned char command;
} __packed_end;

// VS_ETH_STATS.CNF
struct __packed hpav_mtk_vs_eth_stats_cnf {
    // Result
    unsigned char result;
    // The number of good and bad frames received
    unsigned int rx_packets;
    // The number of good frames received
    unsigned int rx_good_packets;
    // The number of good unicast frames received
    unsigned int rx_good_unitcast_packets;
    // The number of good multicast frames received
    unsigned int rx_good_multicast_packets;
    // The number of good broadcast frames received
    unsigned int rx_good_broadcast_packets;
    // The number of total packets received with error
    unsigned int rx_error_packets;
    // The number of missed received frames because of FIFO overflow
    unsigned int rx_fifo_overflow;
    // The number of good and bad frames transmitted, exclusive of retried
    // frames
    unsigned int tx_packets;
    // The umber of good frames transmitted
    unsigned int tx_good_packets;
    // The number of good unicast frames transmitted
    unsigned int tx_good_unitcast_packets;
    // The number of good multicast frames transmitted
    unsigned int tx_good_multicast_packets;
    // The number of good broadcast frames transmitted
    unsigned int tx_good_broadcast_packets;
    // The number of total packets transmitted with error
    unsigned int tx_error_packets;
    // The number of frames aborted because of frame underflow error
    unsigned int tx_fifo_underflow;
    // The number of packets transmit error due to a collision on medium
    unsigned int tx_collision;
    // The Number of frames aborted because of carrier sense error (no carrier
    // or loss of carrier)
    unsigned int tx_carrier_error;
    // Address of STA responding
    unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE];
    // Chain mmes when receiving more than one
    struct hpav_mtk_vs_eth_stats_cnf *next;
} __packed_end;

// VS_GET_STATUS.REQ
struct __packed hpav_mtk_vs_get_status_req {
    // This MME has no content. Padding to please C.
    int padding;
} __packed_end;

// VS_GET_STATUS.CNF
struct __packed hpav_mtk_vs_get_status_cnf {
    // Result
    unsigned char result;
    // Status
    unsigned char status;
    // Is CCO ?
    unsigned char cco;
    // Is preferred CCO ?
    unsigned char preferred_cco;
    // Is backup CCO ?
    unsigned char backup_cco;
    // Is proxy CCO ?
    unsigned char proxy_cco;
    // Is processing Simple Connect ?
    unsigned char simple_connect;
    // Link Connect Status
    unsigned char link_connect_status;
    // Ready for PLC operation
    unsigned char ready_operation;
    // Residual frequency error after frequency offset cerrection (mppm)
    long long freq_error;
    // Frequency offset between the CCo?'s STA_Clk and the STA's STA_Clk (mppm)
    long long freq_offset;
    // System uptime (second)
    long long uptime;
    // Time after station authentication with master (second)
    long long authenticated_time;
    // Count for station authentication with master
    unsigned short int authenticated_count;
    // Address of STA responding
    unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE];
    // Chain mmes when receiving more than one
    struct hpav_mtk_vs_get_status_cnf *next;
} __packed_end;

// VS_GET_TONEMAP.REQ
#define MTK_VS_GET_TONEMAP_INIT_TMI 0xFF
#define MTK_VS_GET_TONEMAP_TX 0x00
#define MTK_VS_GET_TONEMAP_RX 0x01
struct __packed hpav_mtk_vs_get_tonemap_req {
    // MAC address of remote peer station where is applied the requested tonemap
    unsigned char remote_sta_addr[ETH_MAC_ADDRESS_SIZE];
    // Tonemap index
    unsigned char tmi;
    // Current tonemap interval list identifier.
    unsigned char int_id;
    // Tonemap direction
    unsigned char direction;
    // Enable RLE
    unsigned char carrier_group;
} __packed_end;

// VS_GET_TONEMAP.CNF :: Interval list entry
#define MTK_VS_GET_TONEMAP_END_TIME_NS_RES 10240
struct __packed hpav_mtk_tonemap_int_entry {
    // End time of interval in allocation time unit (10.24us)
    unsigned short int_et;
    // Interval tmi
    unsigned char int_tmi;
    // interval rx gain
    int8_t int_rx_gain;
    // interval fec
    unsigned char int_fec;
    // interval gi
    unsigned char int_gi;
    // interval phy rate
    unsigned int int_phy_rate;
} __packed_end;

#if defined(SWIG)
% array_functions(struct hpav_mtk_tonemap_int_entry,
                  hpav_mtk_vs_get__tonemap_int_entry_array);
#endif

#define MTK_VS_GET_TONEMAP_BEACON_START_NS_RES 40
#define MTK_VS_GET_TONEMAP_SUCCESS 0
#define MTK_VS_GET_TONEMAP_FAILURE 1
#define MTK_VS_GET_TONEMAP_BAD_INT_ID 2
struct __packed hpav_mtk_vs_get_tonemap_cnf {
    // Result
    unsigned char result;
    // Delta time between beacon period start and 50/60Hz zero cross (in 25MHz
    // tick = 40ns)
    int beacon_delta;
    // Current tonemap interval list identifier
    unsigned char int_id;
    // Tonemap index of default tonemap
    unsigned char tmi_default;
    // TMI length
    unsigned char tmi_length;
    // TMI data
    unsigned char *tmi_data;
    // INT length
    unsigned char int_length;
    // INT data
    struct hpav_mtk_tonemap_int_entry *int_data;
    // TMI
    unsigned char tmi;
    // FEC code rate of requested tonemap
    int8_t tm_rx_gain;
    // FEC code rate of requested tonemap
    unsigned char tm_fec;
    // Guard interval of requested tonemap
    unsigned char tm_gi;
    // Guard interval of requested tonemap
    unsigned int tm_phy_rate;
    // Carrier Group
    unsigned char carrier_group;
    // Tonemap length or RLE length if RLE is enabled
    unsigned short tonemap_length;
    // Modulation list
    unsigned char modulation_list[MTK_MODULATION_LIST_MAX_SIZE];
    // Address of STA responding
    unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE];
    // Chain mmes when receiving more than one
    struct hpav_mtk_vs_get_tonemap_cnf *next;
} __packed_end;

// VS_SET_CAPTURE_STATE.REQ
struct __packed hpav_mtk_vs_set_capture_state_req {
    // MAC address of remote peer station where is applied the requested
    // SNR/SPECTRUM
    unsigned char remote_sta_addr[ETH_MAC_ADDRESS_SIZE];
    // Station state start/stop
    unsigned char state;
    // Station capture data type
    unsigned char captured;
    // Station capture data source
    unsigned char captured_source;
} __packed_end;

// VS_SET_CAPTURE_STATE.CNF
struct __packed hpav_mtk_vs_set_capture_state_cnf {
    // Result
    unsigned char result;
    // Address of STA responding
    unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE];
    // Chain mmes when receiving more than one
    struct hpav_mtk_vs_set_capture_state_cnf *next;
} __packed_end;

// VS_GET_SNR.REQ
#define MTK_VS_GET_SNR_INIT_INT 0xFF
struct __packed hpav_mtk_vs_get_snr_req {
    // MAC address of remote peer station where is applied the requested SNR
    unsigned char remote_sta_addr[ETH_MAC_ADDRESS_SIZE];
    // Tonemap interval index
    unsigned char int_index;
    // Current tonemap interval list identifier
    unsigned char int_id;
    // Carrier group modulo 4
    unsigned char carrier_group;
} __packed_end;

// VS_GET_SNR.CNF
#define MTK_VS_GET_SNR_SUCCESS 0
#define MTK_VS_GET_SNR_FAILURE 1
#define MTK_VS_GET_SNR_BAD_INT_ID 2
struct __packed hpav_mtk_vs_get_snr_cnf {
    // Result
    unsigned char result;
    // Current tonemap interval list identifier
    unsigned char int_id;
    // number of entries in interval list
    unsigned char int_length;
    // Interval list data
    unsigned short *int_data;
    // Average Bit Error Rate
    unsigned short tm_ber;
    // Carrier group
    unsigned char carrier_group;
    // List of SNR
    unsigned char snr_list[MTK_SNR_LIST_MAX_SIZE];
    // Address of STA responding
    unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE];
    // Chain mmes when receiving more than one
    struct hpav_mtk_vs_get_snr_cnf *next;
} __packed_end;


/** VS_GET_LINK_STATS.REQ ReqType. */
typedef enum cp_msg_vs_get_link_stats_req_reqtype_t {
    HPAV_MTK_VS_GET_LINK_STATS_REQ_REQTYPE_RESET_STAT,
    HPAV_MTK_VS_GET_LINK_STATS_REQ_REQTYPE_GET_STAT,
    HPAV_MTK_VS_GET_LINK_STATS_REQ_REQTYPE_GET_RESET_STAT,
    HPAV_MTK_VS_GET_LINK_STATS_REQ_REQTYPE_NB
} hpav_mtk_vs_link_stats_req_reqtype_t;

/** VS_LINK_STATS.REQ TLFLAG. */
typedef enum cp_msg_vs_link_stats_req_tlflag_t {
    HPAV_MTK_VS_LINK_STATS_REQ_TLFLAG_TX,
    HPAV_MTK_VS_LINK_STATS_REQ_TLFLAG_RX,
    HPAV_MTK_VS_LINK_STATS_REQ_TLFLAG_MNBC,
    HPAV_MTK_VS_LINK_STATS_REQ_TLFLAG_NUM
} hpav_mtk_vs_link_stats_req_tlflag_t;

// VS_GET_LINK_STATS.REQ
struct __packed hpav_mtk_vs_get_link_stats_req {
    // Request Type
    unsigned char req_type;
    // Request identifier
    unsigned char req_id;
    // Link identifier
    unsigned char lid;
    // Transmit link flag
    unsigned char tl_flag;
    // Management link flag
    unsigned char mgmt_flag;
    // Destination/source MAC address
    unsigned char des_src_mac_addr[ETH_MAC_ADDRESS_SIZE];
} __packed_end;

/** VS_GET_LINK_STATS.CNF result. */
typedef enum cp_msg_vs_get_link_stats_cnf_result_t {
    HPAV_MTK_VS_GET_LINK_STATS_CNF_RESULT_SUCCESS,
    HPAV_MTK_VS_GET_LINK_STATS_CNF_RESULT_FAILURE,
    HPAV_MTK_VS_GET_LINK_STATS_CNF_RESULT_NB
} hpav_mtk_vs_link_stats_cnf_result_t;

// VS_GET_LINK_STATS.CNF
struct __packed hpav_mtk_vs_get_link_stats_cnf_tx_stats {
    unsigned int msdu_seg_success;
    unsigned int mpdu;
    unsigned int mpdu_burst;
    unsigned int mpdu_acked;
    unsigned int mpdu_coll;
    unsigned int mpdu_fail;
    unsigned int pb_sucess;
    unsigned int pb_dropped;
    unsigned int pb_crc_fail;
    unsigned int buf_shortage_drop;
} __packed_end;
typedef struct hpav_mtk_vs_get_link_stats_cnf_tx_stats
    hpav_mtk_vs_get_link_stats_cnf_tx_stats;

struct __packed hpav_mtk_vs_get_link_stats_cnf_rx_stats {
    unsigned int msdu_success;
    unsigned int mpdu;
    unsigned int mpdu_burst;
    unsigned int mpdu_acked;
    unsigned int mpdu_fail;
    unsigned int mpdu_icv_fail;
    unsigned int pb;
    unsigned int pb_sucess;
    unsigned int pb_duplicated_dropped;
    unsigned int pb_crc_fail;
    unsigned long long sum_of_ber_in_pb_success;
    unsigned int ssn_under_min;
    unsigned int ssn_over_max;
    unsigned int pb_segs_missed;
} __packed_end;
typedef struct hpav_mtk_vs_get_link_stats_cnf_rx_stats
    hpav_mtk_vs_get_link_stats_cnf_rx_stats;

#define STATS_SIZE 64

struct __packed hpav_mtk_vs_get_link_stats_cnf {
    // Request identifier copied from the corresponding request
    unsigned char req_id;
    // Result
    unsigned char result;
    // Buffer to save Tx/Rx stats
    unsigned char stats[STATS_SIZE];
    // Address of STA responding
    unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE];
    // Chain mmes when receiving more than one
    struct hpav_mtk_vs_get_link_stats_cnf *next;
} __packed_end;

#define CP_DPW_MAX_SIZE 64 // bytes

/** VS_GET_PWM_STATS.CNF MSTATUS. */
typedef enum cp_msg_vs_get_pwm_stats_cnf_mstatus_t {
    HPAV_MTK_VS_GET_PWM_STATS_CNF_MSTATUS_SUCCESS,
    HPAV_MTK_VS_GET_PWM_STATS_CNF_MSTATUS_FAIL,
    HPAV_MTK_VS_GET_PWM_STATS_CNF_MSTATUS_NB
} hpav_mtk_vs_get_pwm_stats_cnf_mstatus_t;

struct __packed hpav_mtk_vs_get_pwm_stats_req {
    // This MME has no content. Padding to please C.
    int padding;
} __packed_end;
typedef struct hpav_mtk_vs_get_pwm_stats_req hpav_mtk_vs_get_pwm_stats_req;

struct __packed hpav_mtk_vs_get_pwm_stats_cnf {
    unsigned char mstatus;
    // PWM frequency
    unsigned short pwm_freq;
    // PWM duty cycle
    unsigned short pwm_duty_cycle;
    // PWM Voltage
    unsigned short pwm_volt;
    // PWM SARADC
    unsigned short pwm_saradc;
    // Address of STA responding
    unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE];
    // Chain MMEs when receiving more than one
    struct hpav_mtk_vs_get_pwm_stats_cnf *next;
} __packed_end;
typedef struct hpav_mtk_vs_get_pwm_stats_cnf hpav_mtk_vs_get_pwm_stats_cnf;

struct __packed hpav_mtk_vs_get_pwm_conf_req {
    // This MME has no content. Padding to please C.
    int padding;
} __packed_end;
typedef struct hpav_mtk_vs_get_pwm_conf_req hpav_mtk_vs_get_pwm_conf_req;

struct __packed hpav_mtk_vs_get_pwm_conf_cnf {
    // PWM mode
    unsigned char pwm_mode;
    // PWM measures
    unsigned char pwm_measures;
    // PWM measurement period
    unsigned short pwm_period;
    // PWM frequency threshold
    unsigned short pwm_freq_thr;
    // PWM duty cycle threshold
    unsigned short pwm_duty_cycle_thr;
    // PWM Voltage threshold
    unsigned short pwm_volt_thr;
    // SARADC LSB
    unsigned short pwm_saradc_lsb;
    // Voltage bias
    unsigned short pwm_voltage_bias;
    // Address of STA responding
    unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE];
    // Chain MMEs when receiving more than one
    struct hpav_mtk_vs_get_pwm_conf_cnf *next;
} __packed_end;
typedef struct hpav_mtk_vs_get_pwm_conf_cnf hpav_mtk_vs_get_pwm_conf_cnf;

struct __packed hpav_mtk_vs_set_pwm_conf_req {
    // OP code
    unsigned char op;
    // PWM mode
    unsigned char pwm_mode;
    // PWM measures
    unsigned char pwm_measures;
    // PWM measurement period
    unsigned short pwm_period;
    // PWM frequency threshold
    unsigned short pwm_freq_thr;
    // PWM duty cycle threshold
    unsigned short pwm_duty_cycle_thr;
    // PWM Voltage threshold
    unsigned short pwm_volt_thr;
    // SARADC LSB
    unsigned short pwm_saradc_lsb;
    // Voltage bias
    unsigned short pwm_voltage_bias;
} __packed_end;
typedef struct hpav_mtk_vs_set_pwm_conf_req hpav_mtk_vs_set_pwm_conf_req;

/** VS_SET_PWM_CONF.CNF MSTATUS. */
typedef enum cp_msg_vs_set_pwm_conf_cnf_mstatus_t {
    HPAV_MTK_VS_SET_PWM_CONF_CNF_MSTATUS_SUCCESS,
    HPAV_MTK_VS_SET_PWM_CONF_CNF_MSTATUS_FAIL,
    HPAV_MTK_VS_SET_PWM_CONF_CNF_MSTATUS_NB
} hpav_mtk_vs_set_pwm_conf_cnf_mstatus_t;

struct __packed hpav_mtk_vs_set_pwm_conf_cnf {
    unsigned char mstatus;
    // Address of STA responding
    unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE];
    // Chain MMEs when receiving more than one
    struct hpav_mtk_vs_set_pwm_conf_cnf *next;
} __packed_end;
typedef struct hpav_mtk_vs_set_pwm_conf_cnf hpav_mtk_vs_set_pwm_conf_cnf;

struct __packed hpav_mtk_vs_spi_stats_req {
    unsigned char command;
} __packed_end;
typedef struct hpav_mtk_vs_spi_stats_req hpav_mtk_vs_spi_stats_req;

struct __packed hpav_mtk_vs_spi_stats_cnf {
    unsigned char result;
    unsigned int rx_packets;
    unsigned int rx_ucast;
    unsigned int rx_cmd_rts;
    unsigned int rx_cmd_rts_err;
    unsigned int rx_cmd_rts_wrong_length;
    unsigned int rx_data_err;
    unsigned int rx_abort_queue_full;
    unsigned short rx_fragment_length;
    unsigned int tx_packets;
    unsigned int tx_ucast;
    unsigned int tx_cmd_rts;
    unsigned int tx_cmd_ctr;
    unsigned int tx_cmd_rts_timeout;
    unsigned int tx_cmd_ctr_timeout;
    unsigned int tx_packet_drop_queue_full;
    unsigned int fragment_expire;
    // Address of STA responding
    unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE];
    // Chain MMEs when receiving more than one
    struct hpav_mtk_vs_spi_stats_cnf *next;

} __packed_end;
typedef struct hpav_mtk_vs_spi_stats_cnf hpav_mtk_vs_spi_stats_cnf;

struct __packed hpav_mtk_vs_set_tx_cali_req {
    // Enable
    unsigned char enable;
} __packed_end;
typedef struct hpav_mtk_vs_set_tx_cali_req hpav_mtk_vs_set_tx_cali_req;

struct __packed hpav_mtk_vs_set_tx_cali_cnf {
    unsigned char result;
    // Address of STA responding
    unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE];
    // Chain MMEs when receiving more than one
    struct hpav_mtk_vs_set_tx_cali_cnf *next;
} __packed_end;
typedef struct hpav_mtk_vs_set_tx_cali_cnf hpav_mtk_vs_set_tx_cali_cnf;

#define SNIF_GP_CAL_NUM_OF_SPECTRUM 1155
struct __packed hpav_mtk_vs_set_tx_cali_ind {
    unsigned short spectrum_idx;
    unsigned char result[SNIF_GP_CAL_NUM_OF_SPECTRUM];
    // Address of STA responding
    unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE];
    // Chain MMEs when receiving more than one
    struct hpav_mtk_vs_set_tx_cali_ind *next;
} __packed_end;
typedef struct hpav_mtk_vs_set_tx_cali_ind hpav_mtk_vs_set_tx_cali_ind;

/** VS_SNIFFER_MODE.CNF MSTATUS. */
typedef enum cp_msg_vs_set_sniffer_conf_cnf_mstatus_t
{
    HPAV_VC_VS_SET_SNIFFER_CONF_CNF_MSTATUS_SUCCESS = 0,
    HPAV_VC_VS_SET_SNIFFER_CONF_CNF_MSTATUS_FAIL = 1,
    HPAV_VC_VS_SET_SNIFFER_CONF_CNF_MSTATUS_NB
} hpav_vc_vs_set_sniffer_conf_cnf_mstatus_t;

/** VS_SET_SNIFFER_ERROR STATUS. */
typedef enum cp_msg_vs_set_sniffer_error_t
{
    HPAV_VC_VS_SET_SNIFFER_ERROR_VALID = 0,
    HPAV_VC_VS_SET_SNIFFER_ERROR_SETTING_FAILED = 1,
    HPAV_VC_VS_SET_SNIFFER_ERROR_NOT_FOUND = 2,
    HPAV_VC_VS_SET_SNIFFER_ERROR_CORRUPTION = 3,
    HPAV_VC_VS_SET_SNIFFER_ERROR_NB
} hpav_vc_vs_set_sniffer_error_t;

struct __packed hpav_vc_vs_set_sniffer_conf_req
{
    unsigned char sniffer_mode;
} __packed_end;
typedef struct hpav_vc_vs_set_sniffer_conf_req
hpav_vc_vs_set_sniffer_conf_req;

struct __packed hpav_vc_vs_set_sniffer_conf_cnf
{
    // Setting status
    unsigned char mstatus;
    // Error status
    unsigned char err_status;
    // MAC address
    unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE];
    // Chain MMEs when receiving more than one
    struct hpav_vc_vs_set_sniffer_conf_cnf* next;
} __packed_end;
typedef struct hpav_vc_vs_set_sniffer_conf_cnf
hpav_vc_vs_set_sniffer_conf_cnf;

struct __packed hpav_vc_vs_set_remote_access_req {
    // REMOTE ACCESS mode
    unsigned char remote_access_mode;
} __packed_end;
typedef struct hpav_vc_vs_set_remote_access_req hpav_vc_vs_set_remote_access_req;

/** VS_SET_REMOTE_ACCESS.CNF MSTATUS. */
typedef enum cp_msg_vc_vs_set_remote_access_cnf_mstatus_t
{
    HPAV_VC_VS_SET_REMOTE_ACCESS_CNF_MSTATUS_SUCCESS = 0,
    HPAV_VC_VS_SET_REMOTE_ACCESS_CNF_MSTATUS_FAIL = 1,
    HPAV_VC_VS_SET_REMOTE_ACCESS_CNF_MSTATUS_OPERATION_IS_PROHIBITED = 255
} hpav_vc_vs_set_remote_access_cnf_mstatus_t;

struct __packed hpav_vc_vs_set_remote_access_cnf {
    unsigned char mstatus;
    // Address of STA responding
    unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE];
    // Chain MMEs when receiving more than one
    struct hpav_vc_vs_set_remote_access_cnf *next;
} __packed_end;
typedef struct hpav_vc_vs_set_remote_access_cnf hpav_vc_vs_set_remote_access_cnf;


/** VS_GET_REMOTE_ACCESS.CNF MSTATUS. */
typedef enum cp_msg_vc_vs_get_remote_access_cnf_mstatus_t {
    HPAV_VC_VS_GET_REMOTE_ACCESS_CNF_MSTATUS_STATION_REMOTE_ACCESS_IS_ALLOWED = 0,
    HPAV_VC_VS_GET_REMOTE_ACCESS_CNF_MSTATUS_STATION_REMOTE_ACCESS_IS_PROHIBITED = 1,
} hpav_vc_vs_get_remote_access_cnf_mstatus_t;

struct __packed hpav_vc_vs_get_remote_access_req {
    // This MME has no content. Padding to please C.
    int padding;
} __packed_end;
typedef struct hpav_vc_vs_get_remote_access_req hpav_vc_vs_get_remote_access_req;

struct __packed hpav_vc_vs_get_remote_access_cnf {
    unsigned char mstatus;
    unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE];
    // Chain MMEs when receiving more than one
    struct hpav_vc_vs_get_remote_access_cnf *next;
} __packed_end;
typedef struct hpav_vc_vs_get_remote_access_cnf hpav_vc_vs_get_remote_access_cnf;

struct __packed hpav_mtk_vs_pwm_generation_req {
    // PWM mode
    unsigned char pwm_mode;
    // PWM frequency
    unsigned short pwm_freq;
    // PWM duty cycle
    unsigned short pwm_duty_cycle;
} __packed_end;

typedef enum cp_msg_vs_pwm_generation_cnf_mstatus_t {
    HPAV_MTK_VS_PWM_GENERATION_CNF_MSTATUS_SUCCESS,
    HPAV_MTK_VS_PWM_GENERATION_CNF_MSTATUS_FAIL,
    HPAV_MTK_VS_PWM_GENERATION_CNF_MSTATUS_NB
} hpav_mtk_vs_pwm_generation_cnf_mstatus_t;

struct __packed hpav_mtk_vs_pwm_generation_cnf {
    unsigned char result;
    // Address of STA responding
    unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE];
    // Chain MMEs when receiving more than one
    struct hpav_mtk_vs_pwm_generation_cnf *next;
} __packed_end;

#define HPAV_MTK_VS_FILE_ACCESS_REQ_DATA_MAX_LEN 1024
#define HPAV_MTK_VS_FILE_ACCESS_CNF_DATA_MAX_LEN 1024
#define HPAV_MTK_VS_FILE_ACCESS_PARAMETER_MAX_LEN 32

/** VS_FILE_ACCESS.CNF MSTATUS. */
typedef enum {
    HPAV_MTK_VS_FILE_ACCESS_CNF_MSTATUS_SUCCESS = 0x00,
    HPAV_MTK_FILE_ACCESS_CNF_MSTATUS_FAIL = 0x01,
} hpav_mtk_vs_file_access_cnf_mstatus_t;

/** VS_FILE_ACCESS.REQ OP. */
typedef enum {
    HPAV_MTK_VS_FILE_ACCESS_REQ_OP_WRITE = 0x00,
    HPAV_MTK_VS_FILE_ACCESS_REQ_OP_READ = 0x01,
    HPAV_MTK_VS_FILE_ACCESS_REQ_OP_DELETE = 0x02,
    HPAV_MTK_VS_FILE_ACCESS_REQ_OP_LIST_DIR = 0x03,
    HPAV_MTK_VS_FILE_ACCESS_REQ_OP_MAKE_DIR = 0x04,
    HPAV_MTK_VS_FILE_ACCESS_REQ_OP_DELETE_DIR = 0x05,
    HPAV_MTK_VS_FILE_ACCESS_REQ_OP_FORMAT_FLASH = 0x06,
    HPAV_MTK_VS_FILE_ACCESS_REQ_OP_SAVE = 0x07,
    HPAV_MTK_VS_FILE_ACCESS_REQ_OP_SCAN_STA = 0x08,
    HPAV_MTK_VS_FILE_ACCESS_REQ_OP_MAX = 0xFF,
} hpav_mtk_vs_file_access_req_op_t;

/** VS_FILE_ACCESS.REQ OP. */
typedef enum {
    HPAV_MTK_VS_FILE_ACCESS_REQ_FILE_TYPE_BOOTLOADER = 0x00,
    HPAV_MTK_VS_FILE_ACCESS_REQ_FILE_TYPE_SIMAGE = 0x01,
    HPAV_MTK_VS_FILE_ACCESS_REQ_FILE_TYPE_GENERAL_FILE = 0x02,
    HPAV_MTK_VS_FILE_ACCESS_REQ_FILE_TYPE_DEBUG = 0x03,
} hpav_mtk_vs_file_access_req_file_type_t;

struct __packed hpav_mtk_vs_file_access_req {
    unsigned char op;
    unsigned char file_type;
    char parameter[HPAV_MTK_VS_FILE_ACCESS_PARAMETER_MAX_LEN];
    u_int16_t total_fragments;
    u_int16_t fragment_number;
    u_int32_t offset;
    u_int32_t checksum;
    u_int16_t length;
    unsigned char data[HPAV_MTK_VS_FILE_ACCESS_REQ_DATA_MAX_LEN];
} __packed_end;
typedef struct hpav_mtk_vs_file_access_req hpav_mtk_vs_file_access_req;

struct __packed hpav_mtk_vs_file_access_cnf {
    unsigned char mstatus;
    unsigned char op;
    unsigned char file_type;
    char parameter[HPAV_MTK_VS_FILE_ACCESS_PARAMETER_MAX_LEN];
    u_int16_t total_fragments;
    u_int16_t fragment_number;
    u_int32_t offset;
    u_int16_t length;
    unsigned char data[HPAV_MTK_VS_FILE_ACCESS_REQ_DATA_MAX_LEN];
    // Address of STA responding
    unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE];
    // Chain MMEs when receiving more than one
    struct hpav_mtk_vs_file_access_cnf *next;
} __packed_end;
typedef struct hpav_mtk_vs_file_access_cnf hpav_mtk_vs_file_access_cnf;

// VS_GET_NW_INFO.REQ
struct __packed hpav_mtk_vs_get_nw_info_req {
    // This MME has no content. Padding to please C.
    int padding;
} __packed_end;

struct __packed hpav_mtk_vs_get_nw_info_entry {

    unsigned char tei;
    // MAC Address of the STA
    unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE];
    // Average PHY Data Rate(coded) in Mega Bits per second from queried STA to
    // this one
    u_int16_t phy_tx_coded;
    // Average PHY Data Rate(raw) in Mega Bits per second from this STA to
    // queried STA
    u_int16_t phy_tx_raw;
    // Average PHY Data Rate(coded) in Mega Bits per second from queried STA to
    // this one
    u_int16_t phy_rx_coded;
    // Average PHY Data Rate(raw) in Mega Bits per second from this STA to
    // queried STA
    u_int16_t phy_rx_raw;
    // AGC gain
    int8_t agc_gain;

} __packed_end;

#if defined(SWIG)
% array_functions(struct hpav_mtk_vs_get_nw_info_entry,
                  hpav_mtk_vs_get_nw_info_entry_array);
#endif

// VS_GET_NW_INFO.CNF
struct __packed hpav_mtk_vs_get_nw_info_cnf {
    // NID of the discovered network
    unsigned char nid[HPAV_NID_SIZE];
    // SNID
    unsigned char snid;
    // CCO TEI
    unsigned char cco_tei;
    // Address of CCO
    unsigned char cco_mac_addr[ETH_MAC_ADDRESS_SIZE];
    // Number of AV STAs in the AVLN
    unsigned char num_nws;
    // Networks info entries
    struct hpav_mtk_vs_get_nw_info_entry *nwinfo;
    // Address of STA responding
    unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE];
    // Chain MMEs when receiving more than one
    struct hpav_mtk_vs_get_nw_info_cnf *next;
} __packed_end;

#define HPAV_MTK_MME_MAX_PAYLOAD 1492 // Regular 1495 minus the three OUI bytes
struct __packed hpav_unknown_mtk_mme {
    unsigned char data[HPAV_MTK_MME_MAX_PAYLOAD];
} __packed_end;

// Mstar MME frame
struct __packed hpav_mtk_mme_header {
    // Management message version
    unsigned char mmv;
    // Management message type
    unsigned short mmtype;
    // FMI
    unsigned char fmi_nf_fn;
    unsigned char fmi_fmsn;
    // Spidcom OUI
    unsigned char oui[HPAV_OUI_SIZE];
} __packed_end;

struct __packed hpav_mtk_mme_frame {
    struct hpav_mtk_mme_header header;
    union {
        // Largest payload possible
        struct hpav_unknown_mtk_mme unknown_mtk_mme;
        struct hpav_mtk_vs_set_nvram_req mtk_vs_set_nvram_req;
        struct hpav_mtk_vs_set_nvram_cnf mtk_vs_set_nvram_cnf;
        struct hpav_mtk_vs_get_version_req mtk_vs_get_version_req;
        struct hpav_mtk_vs_get_version_cnf mtk_vs_get_version_cnf;
        struct hpav_mtk_vs_reset_req mtk_vs_reset_req;
        struct hpav_mtk_vs_reset_cnf mtk_vs_reset_cnf;
        struct hpav_mtk_vs_reset_ind mtk_vs_reset_ind;
        struct hpav_mtk_vs_reset_rsp mtk_vs_reset_rsp;
        struct hpav_mtk_vs_get_nvram_req mtk_vs_get_nvram_req;
        struct hpav_mtk_vs_get_nvram_cnf mtk_vs_get_nvram_cnf;
        struct hpav_mtk_vs_get_tonemask_req mtk_vs_get_tonemask_req;
        struct hpav_mtk_vs_get_tonemask_cnf mtk_vs_get_tonemask_cnf;
        struct hpav_mtk_vs_get_eth_phy_req mtk_vs_get_eth_phy_req;
        struct hpav_mtk_vs_get_eth_phy_cnf mtk_vs_get_eth_phy_cnf;
        struct hpav_mtk_vs_eth_stats_req mtk_vs_eth_stats_req;
        struct hpav_mtk_vs_eth_stats_cnf mtk_vs_eth_stats_cnf;
        struct hpav_mtk_vs_get_status_req mtk_vs_get_status_req;
        struct hpav_mtk_vs_get_status_cnf mtk_vs_get_status_cnf;
        struct hpav_mtk_vs_get_tonemap_req mtk_vs_get_tonemap_req;
        struct hpav_mtk_vs_get_tonemap_cnf mtk_vs_get_tonemap_cnf;
        struct hpav_mtk_vs_set_capture_state_req mtk_vs_set_capture_state_req;
        struct hpav_mtk_vs_set_capture_state_cnf mtk_vs_set_capture_state_cnf;
        struct hpav_mtk_vs_get_snr_req mtk_vs_get_snr_req;
        struct hpav_mtk_vs_get_snr_cnf mtk_vs_get_snr_cnf;
        struct hpav_mtk_vs_get_link_stats_req mtk_vs_get_link_stats_req;
        struct hpav_mtk_vs_get_link_stats_cnf mtk_vs_get_link_stats_cnf;
        struct hpav_mtk_vs_file_access_req hpav_mtk_vs_file_access_req;
        struct hpav_mtk_vs_file_access_cnf hpav_mtk_vs_file_access_cnf;
        struct hpav_mtk_vs_get_pwm_stats_req hpav_mtk_vs_get_pwm_stats_req;
        struct hpav_mtk_vs_get_pwm_stats_cnf hpav_mtk_vs_get_pwm_stats_cnf;
        struct hpav_mtk_vs_get_pwm_conf_req hpav_mtk_vs_get_pwm_conf_req;
        struct hpav_mtk_vs_get_pwm_conf_cnf hpav_mtk_vs_get_pwm_conf_cnf;
        struct hpav_mtk_vs_set_pwm_conf_req hpav_mtk_vs_set_pwm_conf_req;
        struct hpav_mtk_vs_set_pwm_conf_cnf hpav_mtk_vs_set_pwm_conf_cnf;
        struct hpav_mtk_vs_set_tx_cali_req hpav_mtk_vs_set_tx_cali_req;
        struct hpav_mtk_vs_set_tx_cali_cnf hpav_mtk_vs_set_tx_cali_cnf;
        struct hpav_mtk_vs_set_tx_cali_ind hpav_mtk_vs_set_tx_cali_ind;
        struct hpav_vc_vs_set_sniffer_conf_req vc_vs_set_sniffer_conf_req;
        struct hpav_vc_vs_set_sniffer_conf_cnf vc_vs_set_sniffer_conf_cnf;
        struct hpav_vc_vs_set_remote_access_req hpav_vc_vs_set_remote_access_req;
        struct hpav_vc_vs_set_remote_access_cnf hpav_vc_vs_set_remote_access_cnf;
        struct hpav_vc_vs_get_remote_access_req hpav_vc_vs_get_remote_access_req;
        struct hpav_vc_vs_get_remote_access_cnf hpav_vc_vs_get_remote_access_cnf;
    };
};

// Functions declarations

// Support function for raw MME
int hpav_setup_mtk_mme_header(unsigned short mme_type,
                              unsigned int num_fragments,
                              unsigned int fragment_num,
                              unsigned fragment_sequence_number,
                              struct hpav_mtk_mme_header *header);
// Send a raw MME on the channel
int hpav_send_raw_mtk_mme(struct hpav_chan *channel,
                          unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE],
                          struct hpav_mtk_mme_header *header,
                          unsigned char *mme_data, unsigned int mme_data_size);

// Send/receive
HPAV_MME_SNDRCV_DECL(mtk_vs_set_nvram, req, cnf);
HPAV_MME_SNDRCV_DECL(mtk_vs_get_version, req, cnf);
HPAV_MME_SNDRCV_DECL(mtk_vs_reset, req, cnf);
HPAV_MME_SNDRCV_DECL(mtk_vs_get_nvram, req, cnf);
HPAV_MME_SNDRCV_DECL(mtk_vs_get_tonemask, req, cnf);
HPAV_MME_SNDRCV_DECL(mtk_vs_get_eth_phy, req, cnf);
HPAV_MME_SNDRCV_DECL(mtk_vs_eth_stats, req, cnf);
HPAV_MME_SNDRCV_DECL(mtk_vs_get_tonemap, req, cnf);
HPAV_MME_SNDRCV_DECL(mtk_vs_get_status, req, cnf);
HPAV_MME_SNDRCV_DECL(mtk_vs_set_capture_state, req, cnf);
HPAV_MME_SNDRCV_DECL(mtk_vs_get_snr, req, cnf);
HPAV_MME_SNDRCV_DECL(mtk_vs_get_link_stats, req, cnf);
HPAV_MME_SNDRCV_DECL(mtk_vs_get_nw_info, req, cnf);
HPAV_MME_SNDRCV_DECL(mtk_vs_get_pwm_stats, req, cnf);
HPAV_MME_SNDRCV_DECL(mtk_vs_get_pwm_conf, req, cnf);
HPAV_MME_SNDRCV_DECL(mtk_vs_set_pwm_conf, req, cnf);
HPAV_MME_SNDRCV_DECL(mtk_vs_spi_stats, req, cnf);
HPAV_MME_SNDRCV_DECL(mtk_vs_set_tx_cali, req, cnf);
HPAV_MME_SNDRCV_DECL(vc_vs_set_sniffer_conf, req, cnf);
HPAV_MME_SNDRCV_DECL(mtk_vs_pwm_generation, req, cnf);
HPAV_MME_SNDRCV_DECL(vc_vs_set_remote_access, req, cnf);
HPAV_MME_SNDRCV_DECL(vc_vs_get_remote_access, req, cnf);

int hpav_mtk_vs_reset_ind_sndrcv(
    struct hpav_chan *channel, unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE],
    struct hpav_mtk_vs_reset_ind *request,
    struct hpav_mtk_vs_reset_rsp **response, unsigned int timeout_ms,
    unsigned int num_fragments, struct hpav_error **error_stack);
int hpav_mtk_vs_file_access_sndrcv(
    struct hpav_chan *channel, unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE],
    struct hpav_mtk_vs_file_access_req *request,
    struct hpav_mtk_vs_file_access_cnf **response, unsigned int timeout_ms,
    unsigned int num_fragments, struct hpav_error **error_stack,
    unsigned char scan);

int hpav_mtk_vs_set_tx_cali_ind_rcv(
    struct hpav_chan *channel, struct hpav_mtk_vs_set_tx_cali_ind **response,
    unsigned int timeout_ms, unsigned int num_fragments,
    struct hpav_error **error_stack);
#if defined(SWIG)
% pointer_functions(struct hpav_mtk_vs_file_access_cnf *,
                    hpav_mtk_vs_file_access_cnf_pointer);
% pointer_functions(struct hpav_mtk_vs_set_tx_cali_ind *,
                    hpav_mtk_vs_set_tx_cali_ind_pointer);
#endif

// Free functions
HPAV_FREE_STRUCT_DECL(mtk_vs_set_nvram_cnf);
HPAV_FREE_STRUCT_DECL(mtk_vs_get_version_cnf);
HPAV_FREE_STRUCT_DECL(mtk_vs_reset_cnf);
HPAV_FREE_STRUCT_DECL(mtk_vs_reset_rsp)
HPAV_FREE_STRUCT_DECL(mtk_vs_get_nvram_cnf);
HPAV_FREE_STRUCT_DECL(mtk_vs_get_tonemask_cnf);
HPAV_FREE_STRUCT_DECL(mtk_vs_get_eth_phy_cnf);
HPAV_FREE_STRUCT_DECL(mtk_vs_eth_stats_cnf);
HPAV_FREE_STRUCT_DECL(mtk_vs_get_status_cnf);
HPAV_FREE_STRUCT_DECL(mtk_vs_get_tonemap_cnf);
HPAV_FREE_STRUCT_DECL(mtk_vs_set_capture_state_cnf);
HPAV_FREE_STRUCT_DECL(mtk_vs_get_snr_cnf);
HPAV_FREE_STRUCT_DECL(mtk_vs_get_link_stats_cnf);
HPAV_FREE_STRUCT_DECL(mtk_vs_get_pwm_stats_cnf);
HPAV_FREE_STRUCT_DECL(mtk_vs_get_pwm_conf_cnf);
HPAV_FREE_STRUCT_DECL(mtk_vs_set_pwm_conf_cnf);
HPAV_FREE_STRUCT_DECL(mtk_vs_spi_stats_cnf);
HPAV_FREE_STRUCT_DECL(mtk_vs_file_access_cnf);
HPAV_FREE_STRUCT_DECL(mtk_vs_get_nw_info_cnf);
HPAV_FREE_STRUCT_DECL(mtk_vs_set_tx_cali_cnf);
HPAV_FREE_STRUCT_DECL(mtk_vs_set_tx_cali_ind);
HPAV_FREE_STRUCT_DECL(vc_vs_set_sniffer_conf_cnf);
HPAV_FREE_STRUCT_DECL(mtk_vs_pwm_generation_cnf);
HPAV_FREE_STRUCT_DECL(vc_vs_set_remote_access_cnf);
HPAV_FREE_STRUCT_DECL(vc_vs_get_remote_access_cnf);


HPAV_SMART_COPY_STRUCT_DECL(mtk_vs_reset_cnf);
HPAV_SMART_COPY_STRUCT_DECL(mtk_vs_get_version_cnf);
HPAV_SMART_COPY_STRUCT_DECL(mtk_vs_get_nw_info_entry);
HPAV_SMART_COPY_STRUCT_DECL(mtk_vs_get_link_stats_cnf);
HPAV_SMART_COPY_STRUCT_DECL(mtk_vs_set_tx_cali_cnf);
HPAV_SMART_COPY_STRUCT_DECL(mtk_vs_set_tx_cali_ind);
HPAV_SMART_COPY_STRUCT_DECL(vc_vs_set_sniffer_conf_cnf);
HPAV_SMART_COPY_STRUCT_DECL(vc_vs_set_remote_access_cnf);
HPAV_SMART_COPY_STRUCT_DECL(vc_vs_get_remote_access_cnf);


#ifdef _MSC_VER
#pragma pack(pop, hpav)
#else
#endif

#ifdef __cplusplus
}
#endif

#endif //  __HPAV_MTK_API_H__
