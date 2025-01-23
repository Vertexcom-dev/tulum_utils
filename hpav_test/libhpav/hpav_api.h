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
// Home Plug AV 1.0 C API
#ifndef HPAV_API_H
#define HPAV_API_H

#include <stdbool.h>

#ifndef _WIN32
#include <stdlib.h>
#include <string.h>
#endif

// Include pcap.h from libpcap for portable 64-bit integers
#include "pcap.h"

// Need hpav_error in all API calls
#include "hpav_error.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_MSC_VER)
#define __packed
#define __packed_end
#pragma pack(push, hpav, 1)
#else
#define __packed
#define __packed_end __attribute__((packed))
#endif

// Macros for all MMEs type (temporarly here, later in another file for
// convenience)
#define HPAV_MME_SNDRCV_DECL(MME_PREFIX_NAME, MME_REQ_SUFFIX, MME_CNF_SUFFIX)  \
    int hpav_##MME_PREFIX_NAME##_sndrcv(                                       \
        struct hpav_chan *channel, unsigned char sta[ETH_MAC_ADDRESS_SIZE],    \
        struct hpav_##MME_PREFIX_NAME##_##MME_REQ_SUFFIX *request,             \
        struct hpav_##MME_PREFIX_NAME##_##MME_CNF_SUFFIX **response,           \
        unsigned int timeout_ms, unsigned int num_fragments,                   \
        struct hpav_error **error_stack);

#define HPAV_SMART_COPY_STRUCT_DECL(MME_NAME)                                  \
    int hpav_smart_copy_struct_##MME_NAME(struct hpav_##MME_NAME *new_mme,     \
                                          struct hpav_##MME_NAME *mme);

#define HPAV_SMART_COPY_DECL(MME_NAME)                                         \
    int hpav_smart_copy_##MME_NAME(struct hpav_##MME_NAME *new_mme,            \
                                   struct hpav_##MME_NAME *mme);

#define HPAV_FREE_STRUCT_DECL(suffix)                                          \
    int hpav_free_##suffix(struct hpav_##suffix *response);
#define ETH_MAC_ADDRESS_SIZE 6
#define HPAV_NID_SIZE 7
#define HPAV_CID_SIZE 2
#define HPAV_MME_MAX_PAYLOAD 1495
#define HPAV_MD5SUM_SIZE 16
#define HPAV_OUI_SIZE 3

// HPAV Spec macros
// Maximum of carriers from HPAV spec
#define HPAV_POSSIBLE_CARRIERS_MAX 4096
#define HPAV_TONEMASK_SIZE (HPAV_POSSIBLE_CARRIERS_MAX / 8)
#define HPAV_MOD_CARRIER_MAX_SIZE (HPAV_POSSIBLE_CARRIERS_MAX / 2)
#define HPAV_FIRST_CARRIER_FREQUENCY_HZ 0
#define HPAV_CARRIER_SPACING_HZ 24414

// Broadcast address
extern const unsigned char broadcast_mac_addr[ETH_MAC_ADDRESS_SIZE];

// Linux port
#ifndef PCAP_OPENFLAG_PROMISCUOUS
#define PCAP_OPENFLAG_PROMISCUOUS 1
#endif

#ifndef PCAP_OPENFLAG_NOCAPTURE_LOCAL
#define PCAP_OPENFLAG_NOCAPTURE_LOCAL 8
#endif

// Macros

// HPAV standard MMTYPES
#define MMTYPE_CM_ENCRYPTED_PAYLOAD_IND 0x6006
#define MMTYPE_CM_ENCRYPTED_PAYLOAD_RSP 0x6007

#define MMTYPE_CM_SET_KEY_REQ 0x6008
#define MMTYPE_CM_SET_KEY_CNF 0x6009

#define MMTYPE_CM_AMP_MAP_REQ 0x601C
#define MMTYPE_CM_AMP_MAP_CNF 0x601D

// Data structures

// Interface to send/receive Ethernet to/from
struct hpav_if {
    // Next interface in the list, NULL if last interface in the list
    struct hpav_if *next;
    // Interface name to be passed to hpav_open_channel
    char *name;
    // If not NULL, human readable description of the interface
    char *description;
    // MAC address of the interface (all zero if it could not be determined)
    unsigned char mac_addr[ETH_MAC_ADDRESS_SIZE];
};
typedef struct hpav_if hpav_if_t;

// Descriptor for a channel (open interface)
typedef struct hpav_chan {
    // PCAP channel
    pcap_t *pcap_chan;
    // MAC address of the interface (all zero if it could not be determined)
    // (copied from hpav_if)
    unsigned char mac_addr[ETH_MAC_ADDRESS_SIZE];
} hpav_chan_t;

// Network interfaces management

// Returns a list of available ethernet interfaces
int hpav_get_interfaces(struct hpav_if **interface_list,
                        struct hpav_error **error_stack);

// Manage interfaces
struct hpav_if *hpav_get_interface_by_index(struct hpav_if *interfaces,
                                            unsigned int if_num);
struct hpav_if *hpav_get_interface_by_name(struct hpav_if *interfaces,
                                           char *if_name,
                                           unsigned int *if_num);
struct hpav_if *hpav_get_interface_by_index_or_name(struct hpav_if *interfaces,
                                                    char *arg,
                                                    bool *was_index,
                                                    unsigned int *if_num) ;
unsigned int hpav_get_number_of_interfaces(struct hpav_if *interfaces);

// Free a list of interfaces returned by hpav_get_interfaces
int hpav_free_interfaces(struct hpav_if *interface_list);

// Open an interface for further HPAV dialog
hpav_chan_t *hpav_open_channel(struct hpav_if *interface_to_open,
                               struct hpav_error **error_stack);

// Close a channel opened with hpav_open_channel
int hpav_close_channel(struct hpav_chan *channel);

// Security functions
#define HPAV_AES_KEY_SIZE 16
// There are two functions as the salt value in the PBKDF1 algo is not the same
// for NMK and DAK
// Generate a NMK from a NPW
int hpav_generate_nmk(const char *password,
                      unsigned char result[HPAV_AES_KEY_SIZE]);
// Generate a DAK from DPW
int hpav_generate_dak(const char *password,
                      unsigned char result[HPAV_AES_KEY_SIZE]);
// Generate a NID from a NMK. Used to map NID and NMK.
int hpav_generate_nid(const unsigned char nmk[HPAV_AES_KEY_SIZE],
                      unsigned char security_level, unsigned char *nid);

// HPAV MMEs
// CNF structures are partially copied directly from the ETH frame and some
// additional fields are added (sta_mac_addr and next pointer)
// Unknown MME. Just data from MME frame
struct __packed hpav_unknown_mme {
    unsigned char data[HPAV_MME_MAX_PAYLOAD];
} __packed_end;

// CM_UNASSOCIATED_STA.IND
struct __packed hpav_cm_unassociated_sta_ind {
    // Network ID
    unsigned char nid[HPAV_NID_SIZE];
    // CCo Capability
    unsigned char cco_capability;
    // Address of STA responding
    unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE];
    // Chain mmes when receiving more than one
    struct hpav_cm_unassociated_sta_ind *next;
} __packed_end;

// CM_ENCRYPTED_PAYLOAD.IND
#define HPAV_CM_ENCRYPTED_PAYLOAD_UNENCRYPTED_SIZE 24
#define HPAV_CM_ENCRYPTED_PAYLOAD_WITH_DAK 0
#define HPAV_CM_ENCRYPTED_PAYLOAD_WITH_NMK 1
#define HPAV_CM_ENCRYPTED_PAYLOAD_UNECRYPTED 15

struct __packed hpav_cm_encrypted_payload_ind {
    // Payload Encryption Key Select
    unsigned char peks;
    // AVLN status of source
    unsigned char avln_status;
    // Protocol ID
    unsigned char pid;
    // Protocol run number
    unsigned short prn;
    // Protocol message number
    unsigned char pmn;
    // AES encryption Initialization Vector or Universally Unique Identifier
    unsigned char aes_iv[HPAV_AES_KEY_SIZE];
    // Length of MME
    unsigned short mme_length;
    // The above fields can be mapped directly to network data

    // Length of encrypted data
    unsigned short encrypted_data_length;
    // Encrypted data
    unsigned char *encrypted_data;
    // This structure is used for sending and receiving as well
    // Address of STA responding
    unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE];
    // Chain mmes when receiving more than one
    struct hpav_cm_encrypted_payload_ind *next;
} __packed_end;
// CM_ENCRYPTED_PAYLOAD.RSP
// Nothing for this one as it is purely internal when something wrong happens
// during encrypted exchange between two STAs

// CM_SET_KEY.REQ
#define HPAV_CM_SET_KEY_KEY_TYPE_DAK 0
#define HPAV_CM_SET_KEY_KEY_TYPE_NMK 1
#define HPAV_CM_SET_KEY_KEY_TYPE_NEK 2
#define HPAV_CM_SET_KEY_KEY_TYPE_TEK 3
#define HPAV_CM_SET_KEY_KEY_TYPE_HASH 4
#define HPAV_CM_SET_KEY_KEY_TYPE_NOKEY 5

struct __packed hpav_cm_set_key_req {
    // Key type
    unsigned char key_type;
    // Random number that will be used to verify next message from other end; in
    // encrypted portion of payload
    unsigned int my_nonce;
    // Last nonce received from recipient; it will be used by recipient to
    // verify this message; in encrypted portion of payload.
    unsigned int your_nonce;
    // Protocol ID
    unsigned char pid;
    // Protocol run number
    unsigned short prn;
    // Protocol message number
    unsigned char pmn;
    // CCo capability
    unsigned char cco_cap;
    // Network ID to be associated with the key distributed herein
    unsigned char nid[HPAV_NID_SIZE];
    // New Encryption Key Select or New Payload Encryption Key Select depending
    // upon value of Key Type
    unsigned char new_eks;
    // New key
    unsigned char new_key[HPAV_MD5SUM_SIZE];
} __packed_end;
// CM_SET_KEY.CNF
struct __packed hpav_cm_set_key_cnf {
    // Result
    unsigned char result;
    // Random number that will be used to verify next message from other end; in
    // encrypted portion of payload
    unsigned int my_nonce;
    // Last nonce received from recipient; it will be used by recipient to
    // verify this message; in encrypted portion of payload.
    unsigned int your_nonce;
    // Protocol ID
    unsigned char pid;
    // Protocol run number
    unsigned short prn;
    // Protocol message number
    unsigned char pmn;
    // CCo capability
    unsigned char cco_cap;
    // Address of STA responding
    unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE];
    // Chain mmes when receiving more than one
    struct hpav_cm_set_key_cnf *next;
} __packed_end;

// CM_AMP_MAP.REQ
// Need special encoding at sending
struct __packed hpav_cm_amp_map_req {
    // Number of Amplitude Map Data Entries
    unsigned short map_length;
    // Amplitude map data ??? csw changed from unsigned int* map_data;
    unsigned char map_data[2000];
} __packed_end;
// CM_AMP_MAP.CNF
struct __packed hpav_cm_amp_map_cnf {
    // Response type
    unsigned char res_type;
    // Address of STA responding
    unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE];
    // Chain mmes when receiving more than one
    struct hpav_cm_amp_map_cnf *next;
} __packed_end;

// HPAV MME frame (i.e. payload data of an ETH frame)
// Size of MME header without specific content
#define MME_HEADER_SIZE 5
// Macros to extract fragment management information
#define MME_HEADER_NUM_FRAGMENTS_MASK 0x0F
#define MME_HEADER_NUM_FRAGMENTS_SHIFT 0
#define MME_HEADER_FRAGMENT_NUMBER_MASK 0xF0
#define MME_HEADER_FRAGMENT_NUMBER_SHIFT 4
// MME version for standard MMEs
#define MME_HEADER_MMV_HPAV11 1
#define MME_HEADER_MMV_HPAV2 2
// 2 LSB of mmetype represent the MME subtype (�11.1.6 of HPAV spec)
#define MME_HEADER_SUBTYPE_MASK 0x3
#define MME_HEADER_SUBTYPE_SHIFT 0
#define MME_HEADER_SUBTYPE_REQ 0
#define MME_HEADER_SUBTYPE_CNF 1
#define MME_HEADER_SUBTYPE_IND 2
#define MME_HEADER_SUBTYPE_RSP 3

// 3 MSB of mmetype represent the MME category (�11.1.6 of HPAV spec)
#define MME_HEADER_CATEGORY_MASK 0xE000
#define MME_HEADER_CATEGORY_SHIFT 13
#define MME_HEADER_CATEGORY_CC 0
#define MME_HEADER_CATEGORY_CP 1
#define MME_HEADER_CATEGORY_NN 2
#define MME_HEADER_CATEGORY_CM 3
#define MME_HEADER_CATEGORY_MS 4
#define MME_HEADER_CATEGORY_VS 5
// Internal id for MME origin
#define HPAV_UNKNOWN_VENDOR_MME 0
#define HPAV_STANDARD_MME 1
#define HPAV_MTK_MME 2
#define HPAV_INTELLON_MME 3
#define HPAV_GIGLE_MME 4
#define HPAV_ARKADOS_MME 5
#define HPAV_STMICRO_MME 6

struct __packed hpav_mme_header {
    // Management message version
    unsigned char mmv;
    // Management message type
    unsigned short mmtype;
    // FMI
    unsigned char fmi_nf_fn;
    unsigned char fmi_fmsn;
} __packed_end;

struct __packed hpav_mme_frame {
    struct hpav_mme_header header;
    union {
        // Largest payload possible
        struct hpav_unknown_mme unknown_mme;
        // CM_ENCRYPTED_PAYLOAD
        struct hpav_cm_encrypted_payload_ind cm_encrypted_payload_ind;
        // CM_SET_KEY
        struct hpav_cm_set_key_req cm_set_key_req;
        struct hpav_cm_set_key_cnf cm_set_key_cnf;
        // CM_AMP_MAP
        struct hpav_cm_amp_map_req cm_amp_map_req;
        struct hpav_cm_amp_map_cnf cm_amp_map_cnf;
    };
} __packed_end;

// ETH Frame packet
#define ETH_TYPE_SIZE 2
#define ETH_FRAME_MIN_SIZE 60
#define ETH_FRAME_MAX_SIZE                                                     \
    1514 // This doesn't include checksum (managed by libpcap)
#define ETH_FRAME_MAX_PAYLOAD 1500
// ETH header
struct __packed hpav_eth_header {
    unsigned char dst_mac_addr[ETH_MAC_ADDRESS_SIZE];
    unsigned char src_mac_addr[ETH_MAC_ADDRESS_SIZE];
    unsigned char ether_type[ETH_TYPE_SIZE];
} __packed_end;
// ETH packet
struct __packed hpav_eth_frame {
    // Header
    struct hpav_eth_header header;
    // MME data
    struct hpav_mme_frame mme_data;
    // Size of frame to send
    unsigned int frame_size;
    // Time stamp
    struct timeval ts;
    // Chain packets for fragmentation/defragmentation when sending/receiving
    struct hpav_eth_frame *next;
} __packed_end;

// Support function for raw MME
int hpav_setup_mme_header(unsigned short mme_type, unsigned int num_fragments,
                          unsigned int fragment_num,
                          unsigned fragment_sequence_number,
                          struct hpav_mme_header *header);
// Send a raw MME on the channel
int hpav_send_raw_mme(struct hpav_chan *channel,
                      unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE],
                      struct hpav_mme_header *header, unsigned char *mme_data,
                      unsigned int mme_data_size,
                      struct hpav_error **error_stack);

// Sniffing
typedef int (*hpav_sniff_callback)(unsigned char *user_data,
                                   const struct hpav_eth_frame *eth_frame);
int hpav_sniff(struct hpav_chan *channel, hpav_sniff_callback callback,
               unsigned char *user_data, struct hpav_error **error_stack);

// Encrypted payload for CM_SET_KEY
int hpav_cm_set_key_encrypted_sndrcv(
    struct hpav_chan *channel, unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE],
    struct hpav_cm_set_key_req *request, struct hpav_cm_set_key_cnf **response,
    unsigned int timeout_ms, unsigned int num_fragments,
    const char *device_password, struct hpav_error **error_stack);

// HPAV standard MMEs snd/rcv functions declaration
HPAV_MME_SNDRCV_DECL(cm_set_key, req, cnf);
HPAV_MME_SNDRCV_DECL(cm_amp_map, req, cnf);

// Free functions
HPAV_FREE_STRUCT_DECL(cm_set_key_cnf);
HPAV_FREE_STRUCT_DECL(cm_amp_map_cnf);

// Error codes
// Prefix for standard part of core library
// MSByte contains vendor specific code, HPAV standard is 0x00
#define HPAV_ERROR_STANDARD_PREFIX 0x00
// Global OK (no error)
#define HPAV_OK 0x00000000
// Global NOK (-1)
#define HPAV_NOK 0xFFFFFFFF

// Network errors
// A PCAP function returned with an error
#define HPAV_ERROR_PCAP_ERROR 0x00000001
// Parsing error
#define HPAV_ERROR_INPUT_PARSING_ERROR 0x00000002
// Cannot open file
#define HPAV_ERROR_CANNOT_OPEN_FILE 0x00000003
// Network interface error
#define HPAV_ERROR_INTERFACE_ERROR 0x00000004
// SNDRCV error
#define HPAV_ERROR_SNDRCV_ERROR 0x00000005
// STA NOT RESPONDING
#define HPAV_ERROR_STA_NOT_RESPONDING 0x00000006
// Sniffer erreur
#define HPAV_ERROR_SNIFFER 0x00000007

int hpav_unpack(unsigned char input[], int input_size, unsigned char *output[],
                int *output_size);

void hpav_free_unpack_data(unsigned char **input);

#ifdef _MSC_VER
#pragma pack(pop, hpav)
#else
#endif

#ifdef __cplusplus
}
#endif

#endif
