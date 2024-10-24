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
//#ifndef __HPAV_MME_H__
//#define __HPAV_MME_H__

extern const unsigned char broadcast_mac_addr[ETH_MAC_ADDRESS_SIZE];

// Data structures
// Exchange format between user level and eth level (this is never fragmented)
struct __packed hpav_mme_packet {
    // Size of packet
    unsigned int data_size;
    // MME data (header included)
    unsigned char *data;
    // MAC addresses of destination and source
    unsigned char dst_mac_addr[ETH_MAC_ADDRESS_SIZE];
    unsigned char src_mac_addr[ETH_MAC_ADDRESS_SIZE];
    // Chained if necessary
    struct hpav_mme_packet *next;
} __packed_end;

// Common functions

// Free frames
int hpav_free_eth_frames(struct hpav_eth_frame *frames);
int hpav_free_mme_packets(struct hpav_mme_packet *packets);
// Build frames from mme packet, including fragmentation
struct hpav_eth_frame *hpav_build_frames(struct hpav_mme_packet *mme_packets,
                                         unsigned int min_size);
// Build mme packets from ETH frames
struct hpav_mme_packet *hpav_defrag_frames(struct hpav_eth_frame *frames);

#define HPAV_FREE_STRUCT_IMPL(suffix)                                          \
    int hpav_free_##suffix(struct hpav_##suffix *response) {                   \
        while (response != NULL) {                                             \
            struct hpav_##suffix *response_next = response->next;              \
            free(response);                                                    \
            response = response_next;                                          \
        }                                                                      \
        return 0;                                                              \
    }

#define HPAV_ENCODE_MME_IMPL(MME_NAME, MMETYPE_REQ)                            \
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
        unsigned int mme_size =                                                \
            sizeof(struct hpav_mme_header) + sizeof(struct hpav_##MME_NAME);   \
        struct hpav_mme_packet *new_packet =                                   \
            (struct hpav_mme_packet *)malloc(sizeof(struct hpav_mme_packet));  \
        struct hpav_mme_frame *mme_frame = NULL;                               \
        new_mme = (unsigned char *)malloc(mme_size);                           \
        mme_frame = (struct hpav_mme_frame *)new_mme;                          \
        mme_frame->header.mmv = MME_HEADER_MMV_HPAV11; /* HPAV 1.1 (spec       \
                                                          1.0.10 is a          \
                                                          prerelease of 1.1)   \
                                                          */                   \
        mme_frame->header.mmtype = MMETYPE_REQ;                                \
        mme_frame->header.fmi_nf_fn = 0x00;                                    \
        mme_frame->header.fmi_fmsn = 0x00;                                     \
        memcpy(&mme_frame->unknown_mme, request,                               \
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

#define HPAV_SMART_COPY_IMPL(MME_NAME)                                         \
    int hpav_smart_copy_##MME_NAME(struct hpav_##MME_NAME *new_mme,            \
                                   unsigned char *mme_data,                    \
                                   unsigned int mme_data_size) {               \
        memcpy(new_mme, mme_data,                                              \
               sizeof(struct hpav_##MME_NAME) - sizeof(void *) -               \
                   ETH_MAC_ADDRESS_SIZE);                                      \
        return 0;                                                              \
    }

#define HPAV_SMART_COPY_STRUCT_IMPL(MME_NAME)                                  \
    int hpav_smart_copy_struct_##MME_NAME(struct hpav_##MME_NAME *new_mme,     \
                                          struct hpav_##MME_NAME *mme) {       \
        memcpy(new_mme, mme, sizeof(struct hpav_##MME_NAME));                  \
        return 0;                                                              \
    }

#define HPAV_DECODE_MME_IMPL(MME_NAME)                                         \
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
                                                                               \
        while (packets != NULL) {                                              \
            struct hpav_##MME_NAME *new_mme =                                  \
                malloc(sizeof(struct hpav_##MME_NAME));                        \
            /* The CNF struct contains non ETH level data that we don't need   \
               to copy                                                         \
               The MME data contains the MME header, we should read past it */ \
            hpav_smart_copy_##MME_NAME(                                        \
                new_mme, packets->data + sizeof(struct hpav_mme_header),       \
                packets->data_size - sizeof(struct hpav_mme_header));          \
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

typedef struct callback_data {
    unsigned char src_mac_addr[ETH_MAC_ADDRESS_SIZE];
    unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE];
    /* MMType */
    unsigned short int type;
    /* ETH frames received */
    struct hpav_eth_frame *rx_frames;
    /*  Number of expected fragments */
    unsigned int num_fragments;
    /* Indicates that all expected packets are received */
    unsigned short int stop;
    /* Number of fragments received */
    unsigned int num_fragments_received;
    /* ETH packets management */
    struct hpav_eth_frame *latest_frame;
    /* Fragment Number */
    unsigned int fn;
} callback_data_t;

static inline void rx_callback(u_char *user,
                               const struct pcap_pkthdr *packet_header,
                               const u_char *packet_data) {
    /* User data passed to this callback */
    callback_data_t *user_data = (callback_data_t *)user;
    struct hpav_eth_frame *eth_frame = (struct hpav_eth_frame *)packet_data;
    if ((user_data == NULL) || (eth_frame == NULL)) {
        return;
    }

    /* Analyse packet */

    /* Make sure the packet is for the host (case of CM_ENCRYPTED_PAYLOAD.IND)
     */
    if ((memcmp(eth_frame->header.dst_mac_addr, user_data->src_mac_addr,
                ETH_MAC_ADDRESS_SIZE) == 0) &&
        ((eth_frame->mme_data.header.mmtype == user_data->type) ||
         (user_data->type == 0))) /* MMType filter not set => sniff mode */
    {
        /* Right packet found, add to the chain */
        struct hpav_eth_frame *new_frame =
            (struct hpav_eth_frame *)malloc(sizeof(struct hpav_eth_frame));
        memset(new_frame, 0, sizeof(struct hpav_eth_frame));
        memcpy(new_frame, packet_data, packet_header->caplen);
        new_frame->frame_size = packet_header->caplen;
        new_frame->ts = packet_header->ts;

        /* Chain if possible */
        if ((user_data->latest_frame != NULL) &&
            (user_data->type != 0)) /* MMType filter not set => sniff mode */
        {
            user_data->latest_frame->next = new_frame;
        } else {
            /* Record first frame received */
            user_data->rx_frames = new_frame;
        }
        user_data->latest_frame = new_frame;

        /* Set fragment number */
        if (new_frame->frame_size != 0)
            user_data->fn = eth_frame->mme_data.header.fmi_nf_fn & 0xF;
        /* In case message isn't sent in broadcast,
         * stop if number of expected fragments reached */
        user_data->num_fragments_received++;
        if (memcmp(user_data->sta_mac_addr, broadcast_mac_addr,
                   ETH_MAC_ADDRESS_SIZE) &&
            (user_data->num_fragments != 0) &&
            (user_data->num_fragments_received >= user_data->num_fragments)) {
            user_data->stop = 1;
        }
    }
}

#define HPAV_MME_SNDRCV_IMPL(MME_PREFIX_NAME, MME_REQ_SUFFIX, MME_CNF_SUFFIX,  \
                             MMETYPE_CNF)                                      \
    int hpav_##MME_PREFIX_NAME##_sndrcv(                                       \
        struct hpav_chan *channel,                                             \
        unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE],                      \
        struct hpav_##MME_PREFIX_NAME##_##MME_REQ_SUFFIX *request,             \
        struct hpav_##MME_PREFIX_NAME##_##MME_CNF_SUFFIX **response,           \
        unsigned int timeout_ms, unsigned int num_fragments,                   \
        struct hpav_error **error_stack) {                                     \
        /* MME packets */                                                      \
        struct hpav_mme_packet *tx_mme_packets = NULL;                         \
        struct hpav_mme_packet *rx_mme_packets = NULL;                         \
        /* ETH frames */                                                       \
        struct hpav_eth_frame *tx_frames = NULL;                               \
        struct hpav_eth_frame *current_frame = NULL;                           \
        /* Result */                                                           \
        int result = -1;                                                       \
        /* User data passed to pcap_dispatch() callback */                     \
        callback_data_t cb_data;                                               \
        /* Hold compiled program */                                            \
        struct bpf_program fp;                                                 \
        /* Timeout management */                                               \
        struct hpav_sys_time start_time, end_time;                             \
        /* Init callback user data */                                          \
        memset(&cb_data, 0, sizeof(callback_data_t));                          \
        cb_data.type = MMETYPE_CNF;                                            \
        cb_data.num_fragments = num_fragments;                                 \
        /* Source MAC address */                                               \
        memcpy(cb_data.src_mac_addr, channel->mac_addr, ETH_MAC_ADDRESS_SIZE); \
        /* Destination MAC address */                                          \
        memcpy(cb_data.sta_mac_addr, sta_mac_addr, ETH_MAC_ADDRESS_SIZE);      \
        /* Init response */                                                    \
        *response = NULL;                                                      \
                                                                               \
        /* Encode the mme into a buffer */                                     \
        tx_mme_packets = hpav_encode_##MME_PREFIX_NAME##_##MME_REQ_SUFFIX(     \
            cb_data.sta_mac_addr, cb_data.src_mac_addr, request);              \
        /* Build the frames */                                                 \
        tx_frames = hpav_build_frames(tx_mme_packets, ETH_FRAME_MIN_SIZE);     \
        /* TX packets not needed anymore */                                    \
        hpav_free_mme_packets(tx_mme_packets);                                 \
                                                                               \
        /* Compile the program with a filter - non-optimized */                \
        if (pcap_compile(channel->pcap_chan, &fp, "ether proto 0x88E1", 0,     \
                         0) == -1) {                                           \
            char buffer[PCAP_ERRBUF_SIZE + 128];                               \
            sprintf(buffer, "PCAP error code : %d, errbuf : %s", result,       \
                    pcap_geterr(channel->pcap_chan));                          \
            hpav_add_error(error_stack, hpav_error_category_network,           \
                           hpav_error_module_core, HPAV_ERROR_PCAP_ERROR,      \
                           "pcap_compile failed", buffer);                     \
            return HPAV_ERROR_PCAP_ERROR;                                      \
        }                                                                      \
                                                                               \
        /* Set the compiled program as the filter */                           \
        if (pcap_setfilter(channel->pcap_chan, &fp) == -1) {                   \
            char buffer[PCAP_ERRBUF_SIZE + 128];                               \
            sprintf(buffer, "PCAP error code : %d, errbuf : %s", result,       \
                    pcap_geterr(channel->pcap_chan));                          \
            hpav_add_error(error_stack, hpav_error_category_network,           \
                           hpav_error_module_core, HPAV_ERROR_PCAP_ERROR,      \
                           "pcap_setfilter failed", buffer);                   \
            return HPAV_ERROR_PCAP_ERROR;                                      \
        }                                                                      \
                                                                               \
        /* Send the frames */                                                  \
        current_frame = tx_frames;                                             \
        while (current_frame != NULL) {                                        \
            result = pcap_sendpacket(channel->pcap_chan,                       \
                                     (unsigned char *)current_frame,           \
                                     current_frame->frame_size);               \
            if (result != 0) {                                                 \
                /* PCAP error */                                               \
                char buffer[PCAP_ERRBUF_SIZE + 128];                           \
                sprintf(buffer, "PCAP error code : %d, errbuf : %s", result,   \
                        pcap_geterr(channel->pcap_chan));                      \
                hpav_add_error(error_stack, hpav_error_category_network,       \
                               hpav_error_module_core, HPAV_ERROR_PCAP_ERROR,  \
                               "pcap_sendpacket failed", buffer);              \
                hpav_free_eth_frames(tx_frames);                               \
                return HPAV_ERROR_PCAP_ERROR;                                  \
            }                                                                  \
            current_frame = current_frame->next;                               \
        }                                                                      \
        /* TX frames not needed anymore */                                     \
        hpav_free_eth_frames(tx_frames);                                       \
                                                                               \
        /* Receive the frames. If timeout is zero, don't attempt reception. */ \
        if (timeout_ms > 0) {                                                  \
            /* Init start time */                                              \
            hpav_get_sys_time(&start_time);                                    \
                                                                               \
            /* We loop until we have collected all the packets with the right  \
             * Ethertype and MME type */                                       \
            do {                                                               \
                result = pcap_dispatch(channel->pcap_chan, -1, rx_callback,    \
                                       (u_char *)&cb_data);                    \
                if (result > 0) {                                              \
                    /* PCAP: number of  packets  processed  on  success */     \
                } else if (result == 0) {                                      \
                    /* PCAP: no packets to read */                             \
                } else if (result == -1) {                                     \
                    /* PCAP: error occured */                                  \
                    char buffer[PCAP_ERRBUF_SIZE + 128];                       \
                    sprintf(buffer, "PCAP error code : %d, errbuf : %s",       \
                            result, pcap_geterr(channel->pcap_chan));          \
                    hpav_add_error(error_stack, hpav_error_category_network,   \
                                   hpav_error_module_core,                     \
                                   HPAV_ERROR_PCAP_ERROR,                      \
                                   "pcap_dispatch failed", buffer);            \
                    hpav_free_eth_frames(cb_data.rx_frames);                   \
                    return HPAV_ERROR_PCAP_ERROR;                              \
                } else /* (result == -2) */                                    \
                {                                                              \
                    /* PCAP: the loop terminated due to a call to              \
                     * pcap_breakloop() before any packets were  processed */  \
                }                                                              \
                                                                               \
                /* Compute elapsed time */                                     \
                hpav_get_sys_time(&end_time);                                  \
                                                                               \
                /* Exit loop when caller timeout is reached */                 \
            } while ((hpav_get_elapsed_time_ms(&start_time, &end_time) <=      \
                      (int)timeout_ms) &&                                      \
                     !cb_data.stop);                                           \
                                                                               \
            /* Defragment frames */                                            \
            rx_mme_packets = hpav_defrag_frames(cb_data.rx_frames);            \
            /* RX Frames not needed anymore */                                 \
            hpav_free_eth_frames(cb_data.rx_frames);                           \
                                                                               \
            /* Build user level MMEs (MME type specific) */                    \
            *response = hpav_decode_##MME_PREFIX_NAME##_##MME_CNF_SUFFIX(      \
                rx_mme_packets);                                               \
                                                                               \
            /* RX MME packets not needed anymore */                            \
            hpav_free_mme_packets(rx_mme_packets);                             \
        }                                                                      \
                                                                               \
        return HPAV_OK;                                                        \
    }

// Expose some functions for testing
struct hpav_cm_encrypted_payload_ind *
hpav_encrypt_with_dak(struct hpav_eth_frame *tx_eth_frame,
                      const char *device_password);

int hpav_free_cm_encrypted_payload_ind(
    struct hpav_cm_encrypted_payload_ind *response);
//#endif // __HPAV_MME_H__
