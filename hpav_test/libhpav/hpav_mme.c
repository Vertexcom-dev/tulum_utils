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
// Implementation of HPAV standard MME send/receive

// Avoid unnecessary warnings with VC
#define _CRT_SECURE_NO_WARNINGS 1

#include "pcap.h"
#include "hpav_api.h"
#include "hpav_utils.h"
#include "hpav_mme.h"
#include "hpav_mtk_api.h"

// For crc32 used in encrypted payload
#include "zlib.h"

// AES encryption from OpenSSL
#include "openssl/aes.h"

const unsigned char broadcast_mac_addr[ETH_MAC_ADDRESS_SIZE] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

int hpav_free_cm_encrypted_payload_ind(
    struct hpav_cm_encrypted_payload_ind *response) {
    while (response != NULL) {
        struct hpav_cm_encrypted_payload_ind *response_next = response->next;
        free(response->encrypted_data);
        free(response);
        response = response_next;
    }
    return 0;
}

HPAV_FREE_STRUCT_IMPL(cm_set_key_cnf);
HPAV_FREE_STRUCT_IMPL(cm_amp_map_cnf);

// Free chained ETH frames
int hpav_free_eth_frames(struct hpav_eth_frame *frames) {
    while (frames != NULL) {
        struct hpav_eth_frame *frame_next = frames->next;
        free(frames);
        frames = frame_next;
    }
    return 0;
}

// Free chained MME packets
int hpav_free_mme_packets(struct hpav_mme_packet *packets) {
    while (packets != NULL) {
        struct hpav_mme_packet *packet_next = packets->next;
        free(packets->data);
        free(packets);
        packets = packet_next;
    }
    return 0;
}

// Build ETH frames with fragmentation if required
// Support for multiple MME packets for the future
struct hpav_eth_frame *hpav_build_frames(struct hpav_mme_packet *mme_packets,
                                         unsigned int min_size) {
    // Check payload size (does it fit in one Ethernet frame)
    if (mme_packets->data_size <= ETH_FRAME_MAX_PAYLOAD) {
        // If the mme size is smaller than the maximum payload, build one simple
        // frame
        struct hpav_eth_frame *new_frame =
            malloc(sizeof(struct hpav_eth_frame));
        memset(new_frame, 0, sizeof(struct hpav_eth_frame));
        // ETH header data
        memcpy(new_frame->header.dst_mac_addr, mme_packets->dst_mac_addr,
               ETH_MAC_ADDRESS_SIZE);
        memcpy(new_frame->header.src_mac_addr, mme_packets->src_mac_addr,
               ETH_MAC_ADDRESS_SIZE);
        new_frame->header.ether_type[0] = 0x88; // MME ETH type
        new_frame->header.ether_type[1] = 0xE1; //
        // Copy mme in frame
        memcpy(&new_frame->mme_data, mme_packets->data, mme_packets->data_size);
        // Set the frame size
        new_frame->frame_size =
            sizeof(struct hpav_eth_header) + mme_packets->data_size;
        if (new_frame->frame_size < min_size) {
            new_frame->frame_size = min_size;
        }
        return new_frame;
    } else {
        // Needs fragmentation at sending. Not supported at the moment.
        // A NULL pointer is returned and nothing is sent.
    }
    return NULL; // Nothing to send
}

// Group nodes (kept in order of reception)
struct hpav_defrag_group {
    // ETH frame in this group
    struct hpav_eth_frame *frame;
    // Chain frames in this group
    struct hpav_defrag_group *next;
};

struct hpav_defrag_group_list {
    // Group
    struct hpav_defrag_group *group;
    // Chain groups
    struct hpav_defrag_group_list *next;
};

// Free frame group
int hpav_defrag_free_groups(struct hpav_defrag_group *groups) {
    while (groups != NULL) {
        struct hpav_defrag_group *group_next = groups->next;
        free(groups);
        groups = group_next;
    }
    return 0;
}

// Free frame group list
int hpav_defrag_free_group_list(struct hpav_defrag_group_list *group_list) {
    while (group_list != NULL) {
        struct hpav_defrag_group_list *group_list_next = group_list->next;
        hpav_defrag_free_groups(group_list->group);
        free(group_list);
        group_list = group_list_next;
    }
    return 0;
}

// Find a group for this frame
int hpav_defrag_add_to_group_list(struct hpav_defrag_group_list *group_list,
                                  struct hpav_eth_frame *frame) {
    // Group for the frame
    struct hpav_defrag_group *group_found = NULL;
    // Group node for finding the last node
    struct hpav_defrag_group *current_group = NULL;
    // Last group node to add to the chain
    struct hpav_defrag_group *last_group = NULL;

    // Last group in the group list (could be recomputed later, but better to
    // save it during the loop)
    struct hpav_defrag_group_list *last_group_list = NULL;

    while (group_list != NULL) {
        // Check unique key identifier (see 11.1.7 in HPAV 1.1 documentation)
        // The group cannot be empty (by construction, but check anyway)
        if (group_list->group != NULL) {
            if (memcmp(group_list->group->frame->header.dst_mac_addr,
                       frame->header.dst_mac_addr, ETH_MAC_ADDRESS_SIZE) == 0 &&
                memcmp(group_list->group->frame->header.src_mac_addr,
                       frame->header.src_mac_addr, ETH_MAC_ADDRESS_SIZE) == 0 &&
                group_list->group->frame->mme_data.header.mmv ==
                    frame->mme_data.header.mmv &&
                group_list->group->frame->mme_data.header.mmtype ==
                    frame->mme_data.header.mmtype &&
                group_list->group->frame->mme_data.header.fmi_fmsn ==
                    frame->mme_data.header.fmi_fmsn) {
                // Key match : use this group for new frame
                group_found = group_list->group;
            }
        }
        last_group_list = group_list;
        group_list = group_list->next;
    }

    // If no group found, create new group and add to group list
    if (group_found == NULL) {
        group_found = malloc(sizeof(struct hpav_defrag_group));
        memset(group_found, 0, sizeof(struct hpav_defrag_group));
        if (last_group_list->group == NULL) {
            // This case is for the first group added to the list as the caller
            // allocates an empty group_list to start with
            last_group_list->group = group_found;
        } else {
            // Standard case, we allocate a group_list node
            struct hpav_defrag_group_list *new_group_list =
                malloc(sizeof(struct hpav_defrag_group_list));
            new_group_list->group = group_found;
            new_group_list->next = NULL;
            last_group_list->next = new_group_list;
        }
        group_found->frame = frame;
    } else {
        // Allocate a new group node and chain
        struct hpav_defrag_group *new_group =
            malloc(sizeof(struct hpav_defrag_group));
        new_group->frame = frame;
        new_group->next = NULL;

        // Find the last group node for chaining
        current_group = group_found;
        while (current_group != NULL) {
            last_group = current_group;
            current_group = current_group->next;
        }
        last_group->next = new_group;
    }
    return 0;
}

// Create a new packet from a group of frames with same key and that should be
// in the right fragment order
struct hpav_mme_packet *
hpav_defrag_grouped_frames(struct hpav_defrag_group *group) {
    // Group cannot be empty (by construction) but chek anyway to avoid crashes
    if (group->frame == NULL) {
        return NULL;
    } else {
        // Current group node
        struct hpav_defrag_group *current_group = NULL;
        // New packet to return to caller
        struct hpav_mme_packet *new_packet = NULL;
        // Fragment index
        unsigned int fragment_index = 0;
        // Current data buffer when copying fragments
        unsigned char *current_data_buffer = NULL;

        // Check if all fragments are present
        // CAUTION : starts at 0
        unsigned int expected_num_fragments =
            ((group->frame->mme_data.header.fmi_nf_fn &
              MME_HEADER_NUM_FRAGMENTS_MASK) >>
             MME_HEADER_NUM_FRAGMENTS_SHIFT);
        unsigned int total_fragment_number = 0;
        unsigned int size_of_mme_header = 0;

        current_group = group;
        while (current_group != NULL) {
            unsigned int current_fragment_number =
                ((current_group->frame->mme_data.header.fmi_nf_fn &
                  MME_HEADER_FRAGMENT_NUMBER_MASK) >>
                 MME_HEADER_FRAGMENT_NUMBER_SHIFT);

            // PATCH to improve.
            if (current_group == group) {
                if ((current_group->frame->mme_data.header.mmtype & 0xE000) ==
                    0xA000) {
                    size_of_mme_header = sizeof(struct hpav_mtk_mme_header);
                } else {
                    size_of_mme_header = sizeof(struct hpav_mme_header);
                }
            }

            if (current_fragment_number != total_fragment_number) {
                printf("%s:%d  Out of order\n", __FILE__, __LINE__);
                // Out of order or missing fragments
                return NULL;
            }
            total_fragment_number++;
            current_group = current_group->next;
        }

        if ((expected_num_fragments + 1) != total_fragment_number) {
            // Missing fragments
            printf("%s:%d  Missing fragments\n", __FILE__, __LINE__);
            return NULL;
        }

        // New packet to return to caller
        new_packet = malloc(sizeof(struct hpav_mme_packet));

        // New packet
        memset(new_packet, 0, sizeof(struct hpav_mme_packet));
        memcpy(new_packet->dst_mac_addr, group->frame->header.dst_mac_addr,
               ETH_MAC_ADDRESS_SIZE);
        memcpy(new_packet->src_mac_addr, group->frame->header.src_mac_addr,
               ETH_MAC_ADDRESS_SIZE);

        // Loop on all frames to compute total size
        current_group = group;
        while (current_group != NULL) {
            // Payload size is frame size minus ETH header and MME header
            new_packet->data_size += current_group->frame->frame_size -
                                     sizeof(struct hpav_eth_header) -
                                     size_of_mme_header;
            current_group = current_group->next;
        }

        // Allocate buffer for MME data (this time one header is required)
        new_packet->data_size += size_of_mme_header;
        new_packet->data = malloc(new_packet->data_size);
        // Loop once more to copy the data
        current_group = group;
        fragment_index = 0;
        current_data_buffer = new_packet->data;
        while (current_group != NULL) {
            int size_to_copy = 0;
            unsigned char *ptr_begin;

            // Copy MME data, header included for the first one
            if (fragment_index == 0) {
                ptr_begin = (unsigned char *)&current_group->frame->mme_data;
                size_to_copy = current_group->frame->frame_size -
                               sizeof(struct hpav_eth_header);
            } else {
                ptr_begin = ((unsigned char *)&current_group->frame->mme_data) +
                            size_of_mme_header;
                size_to_copy = current_group->frame->frame_size -
                               sizeof(struct hpav_eth_header) -
                               size_of_mme_header;
            }

            memcpy(current_data_buffer, ptr_begin, size_to_copy);
            current_data_buffer += size_to_copy;
            current_group = current_group->next;
            fragment_index++;
        }

        // Return packet built
        return new_packet;
    }
}

// Build mme packets from ETH frames
struct hpav_mme_packet *hpav_defrag_frames(struct hpav_eth_frame *frames) {
    // Two steps :
    // - regroup frames by unique id : dest, src, mmv, mmtype, fmsn
    // (the algorithm is at least in n^2 but this should not be a problem with
    // the size of the data set
    //  this could be easily made nlogn with a hash/tree map)
    // - for each group build a MME packet from the fragments

    // Packets to return
    struct hpav_mme_packet *new_packets = NULL;
    // Last packet for chaining
    struct hpav_mme_packet *last_packet = NULL;

    // Current group_list node
    struct hpav_defrag_group_list *current_group_list = NULL;

    // Current frame in loop
    struct hpav_eth_frame *current_frame = frames;
    // Group list
    struct hpav_defrag_group_list *group_list =
        malloc(sizeof(struct hpav_defrag_group_list));
    memset(group_list, 0, sizeof(struct hpav_defrag_group_list));

    while (current_frame != NULL) {
        // Add frame to the group_list
        hpav_defrag_add_to_group_list(group_list, current_frame);
        current_frame = current_frame->next;
    }

    // Regroup frames
    current_group_list = group_list;
    while (current_group_list != NULL) {
        // Current group node
        struct hpav_defrag_group *current_group = current_group_list->group;
        if (current_group != NULL) { // Cas NULL when the group_list is empty
            // New MME packet for this group
            struct hpav_mme_packet *new_mme_packet =
                hpav_defrag_grouped_frames(current_group);
            if (new_mme_packet == NULL) {
                // erreur de d�fragmentation
            }
            if (new_packets == NULL) {
                new_packets = new_mme_packet;
            } else {
                last_packet->next = new_mme_packet;
            }
            last_packet = new_mme_packet;
        }
        current_group_list = current_group_list->next;
    }

    hpav_defrag_free_group_list(group_list);

    return new_packets;
}

HPAV_ENCODE_MME_IMPL(cm_set_key_req, MMTYPE_CM_SET_KEY_REQ);

struct hpav_mme_packet *
hpav_encode_cm_amp_map_req(unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE],
                           unsigned char src_mac_addr[ETH_MAC_ADDRESS_SIZE],
                           struct hpav_cm_amp_map_req *request) {
    unsigned char *new_mme = NULL;
    unsigned int map_data_size =
        ((request->map_length) / 2 + (request->map_length) % 2) *
        sizeof(unsigned char);
    unsigned int mme_size =
        sizeof(struct hpav_mme_header) + sizeof(unsigned short) + map_data_size;
    struct hpav_mme_packet *new_packet =
        (struct hpav_mme_packet *)malloc(sizeof(struct hpav_mme_packet));
    struct hpav_mme_frame *mme_frame = NULL;
    new_mme = (unsigned char *)malloc(mme_size);
    mme_frame = (struct hpav_mme_frame *)new_mme;
    mme_frame->header.mmv =
        MME_HEADER_MMV_HPAV11; /* HPAV 1.1 (spec 1.0.10 is a prerelease
                                  of 1.1) */
    mme_frame->header.mmtype = MMTYPE_CM_AMP_MAP_REQ;
    mme_frame->header.fmi_nf_fn = 0x00;
    mme_frame->header.fmi_fmsn = 0x00;
    // Effective payload
    mme_frame->cm_amp_map_req.map_length = request->map_length;
    // We reuse the data structure for convenience,
    memcpy(&mme_frame->cm_amp_map_req.map_data, request->map_data,
           map_data_size);

    new_packet->data_size = mme_size;
    new_packet->data = new_mme;
    memcpy(new_packet->dst_mac_addr, sta_mac_addr, ETH_MAC_ADDRESS_SIZE);
    memcpy(new_packet->src_mac_addr, src_mac_addr, ETH_MAC_ADDRESS_SIZE);
    new_packet->next = NULL;
    return new_packet;
}

struct hpav_mme_packet *hpav_encode_cm_encrypted_payload_ind(
    unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE],
    unsigned char src_mac_addr[ETH_MAC_ADDRESS_SIZE],
    struct hpav_cm_encrypted_payload_ind *request) {
    unsigned char *new_mme = NULL;
    // MME size : all unencrypted fields + encryption payload
    unsigned int mme_size = sizeof(struct hpav_mme_header) +
                            24 // Size of unencrypted portion of the message
                            + request->encrypted_data_length;
    struct hpav_mme_packet *new_packet =
        (struct hpav_mme_packet *)malloc(sizeof(struct hpav_mme_packet));
    struct hpav_mme_frame *mme_frame = NULL;
    new_mme = (unsigned char *)malloc(mme_size);
    mme_frame = (struct hpav_mme_frame *)new_mme;
    mme_frame->header.mmv =
        MME_HEADER_MMV_HPAV11; /* HPAV 1.1 (spec 1.0.10 is a prerelease
                                  of 1.1) */
    mme_frame->header.mmtype = MMTYPE_CM_ENCRYPTED_PAYLOAD_IND;
    mme_frame->header.fmi_nf_fn = 0x00;
    mme_frame->header.fmi_fmsn = 0x00;
    // Unencrypted part
    memcpy(&mme_frame->cm_encrypted_payload_ind.peks, request,
           HPAV_CM_ENCRYPTED_PAYLOAD_UNENCRYPTED_SIZE);
    // Encrypted part
    memcpy(&mme_frame->cm_encrypted_payload_ind.peks +
               HPAV_CM_ENCRYPTED_PAYLOAD_UNENCRYPTED_SIZE,
           request->encrypted_data, request->encrypted_data_length);

    new_packet->data_size = mme_size;
    new_packet->data = new_mme;
    memcpy(new_packet->dst_mac_addr, sta_mac_addr, ETH_MAC_ADDRESS_SIZE);
    memcpy(new_packet->src_mac_addr, src_mac_addr, ETH_MAC_ADDRESS_SIZE);
    new_packet->next = NULL;
    return new_packet;
}

int hpav_smart_copy_cm_encrypted_payload_ind(
    struct hpav_cm_encrypted_payload_ind *response, unsigned char *mme_data,
    unsigned int mme_data_size) {
    // Copy unencrypted part
    memcpy(response, mme_data, HPAV_CM_ENCRYPTED_PAYLOAD_UNENCRYPTED_SIZE);
    // Copy encrypted part
    response->encrypted_data_length =
        mme_data_size - HPAV_CM_ENCRYPTED_PAYLOAD_UNENCRYPTED_SIZE;
    response->encrypted_data =
        (unsigned char *)malloc(response->encrypted_data_length);
    memcpy(response->encrypted_data,
           mme_data + HPAV_CM_ENCRYPTED_PAYLOAD_UNENCRYPTED_SIZE,
           response->encrypted_data_length);

    return 0;
}

HPAV_SMART_COPY_IMPL(cm_set_key_cnf);
HPAV_SMART_COPY_IMPL(cm_amp_map_cnf);
// HPAV_SMART_COPY_IMPL(cm_hfid_cnf);

HPAV_DECODE_MME_IMPL(cm_encrypted_payload_ind);
HPAV_DECODE_MME_IMPL(cm_set_key_cnf);
HPAV_DECODE_MME_IMPL(cm_amp_map_cnf);

HPAV_MME_SNDRCV_IMPL(cm_encrypted_payload, ind, ind,
                     MMTYPE_CM_ENCRYPTED_PAYLOAD_IND);
HPAV_MME_SNDRCV_IMPL(cm_set_key, req, cnf, MMTYPE_CM_SET_KEY_CNF);
HPAV_MME_SNDRCV_IMPL(cm_amp_map, req, cnf, MMTYPE_CM_AMP_MAP_CNF);

#include "openssl/rand.h"
// Encrypt a ETH packet into a cm_encrypted_payload_ind data structure using DAK
// encryption
// (simpler version which doesn't support chained packets, can be extended in
// the future)
// Assume the ETH packet is a CM_SET_KEY (we copy some fields from the payload
// MME into the CM_ENCRYPTED_PAYLOAD)
struct hpav_cm_encrypted_payload_ind *
hpav_encrypt_with_dak(struct hpav_eth_frame *tx_eth_frame,
                      const char *device_password) {
    // Build the payload part which needs to be encrypted
    // CAUTION : the MME to be encrypted is the whole ETH packet, not only the
    // MME payload of the ETH packet
    //
    // Total size is :
    // random filler 0-15 bytes
    // + eth frame size
    // + checksum 4 bytes
    // + pid 1 byte
    // + prn 2 bytes
    // + pmn 1 byte
    // + padding 0-15 (adjust 128-bit boundary for AES encryption)
    // + length of random filler 1 byte

    unsigned char rand_byte;
    unsigned int rand_filler_size;
    unsigned int padding_size;

    unsigned int total_size;
    unsigned char *data_to_encrypt = NULL;
    unsigned char *encrypted_data = NULL;
    unsigned char *current_data = NULL;

    struct hpav_cm_encrypted_payload_ind *tx_encrypted_mme;

    unsigned int data_crc;

    unsigned char dak[HPAV_AES_KEY_SIZE];

    // Initialization vector per HPAV 1.1 spec (Table 13-6)
    unsigned char aes_iv[HPAV_AES_KEY_SIZE] = {
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};

    AES_KEY aes_key;

    if (tx_eth_frame == NULL) {
        return NULL;
    }
    // If there is no payload (tx_mme_packets->data_size == 0), we expect to
    // send an encrypted mme with empty payload (to be tested)

    // Get random number (use OpenSSL for convenience)
    RAND_bytes(&rand_byte, 1);
    rand_filler_size = (rand_byte & 0xF);
    rand_filler_size = 5; // TESTING
    total_size =
        rand_filler_size + tx_eth_frame->frame_size + 4 + 1 + 2 + 1 + 1;
    // Pad for 128-bit alignment
    padding_size = (16 - (total_size & 0xF)) & 0xF;
    total_size += padding_size;
    // Allocate results
    data_to_encrypt = (unsigned char *)malloc(total_size);
    encrypted_data = (unsigned char *)malloc(total_size);
    tx_encrypted_mme = (struct hpav_cm_encrypted_payload_ind *)malloc(
        sizeof(struct hpav_cm_encrypted_payload_ind));
    memset(tx_encrypted_mme, 0, sizeof(struct hpav_cm_encrypted_payload_ind));
    // Set MME fields
    tx_encrypted_mme->peks = 0; // Destination STA DAK
    tx_encrypted_mme->avln_status =
        0; // ??? Not sure what to put here : 5 for testing //TESTING
    tx_encrypted_mme->pid = tx_eth_frame->mme_data.cm_set_key_req.pid;
    tx_encrypted_mme->prn = tx_eth_frame->mme_data.cm_set_key_req.prn;
    tx_encrypted_mme->pmn = tx_eth_frame->mme_data.cm_set_key_req.pmn;
    memcpy(tx_encrypted_mme->aes_iv, aes_iv,
           HPAV_AES_KEY_SIZE); // AES initialization vector
    tx_encrypted_mme->mme_length = tx_eth_frame->frame_size; // MME length
    tx_encrypted_mme->encrypted_data_length = total_size;

    // Set fields in the encrypted payload itself
    current_data = data_to_encrypt;
    // Random filler
    RAND_bytes(current_data, rand_filler_size);
    //  current_data[0] = 0x24; //TESTING
    //  current_data[1] = 0x68; //TESTING
    //  current_data[2] = 0xAC; //TESTING
    //  current_data[3] = 0xE0; //TESTING
    //  current_data[4] = 0x35; //TESTING
    current_data += rand_filler_size;
    // Payload
    memcpy(current_data, tx_eth_frame, tx_eth_frame->frame_size);
    current_data += tx_eth_frame->frame_size;
    // CRC (provided by zlib)
    data_crc = crc32(0, NULL, 0);
    data_crc = crc32((unsigned long)data_crc, (char *)tx_eth_frame, tx_eth_frame->frame_size);
    *((unsigned int *)current_data) = data_crc;
    current_data += sizeof(unsigned int);
    // PID
    *current_data = tx_encrypted_mme->pid;
    current_data++;
    // PRN
    *((unsigned short *)current_data) = tx_encrypted_mme->prn;
    current_data += sizeof(unsigned short);
    // PMN
    *current_data = tx_encrypted_mme->pmn;
    current_data++;
    // Padding
    RAND_bytes(current_data, padding_size);
    //  current_data[0] = 0xAC; //TESTING
    //  current_data[1] = 0xBC; //TESTING
    //  current_data[2] = 0xD2; //TESTING
    //  current_data[3] = 0x11; //TESTING
    //  current_data[4] = 0x4D; //TESTING
    //  current_data[5] = 0xAE; //TESTING
    //  current_data[6] = 0x15; //TESTING
    //  current_data[7] = 0x77; //TESTING
    //  current_data[8] = 0xC6; //TESTING
    current_data += padding_size;
    // Length of random filler
    *current_data = rand_filler_size;

    // Generate DAK from password
    hpav_generate_dak(device_password, dak);

    // Encrypt payload with AES
    AES_set_encrypt_key(dak, HPAV_AES_KEY_SIZE * 8, &aes_key);
    // CAUTION : aes_iv is modified during this function call, so don't reuse it
    // later unless you know what you are doing.
    AES_cbc_encrypt(data_to_encrypt, encrypted_data, total_size, &aes_key,
                    aes_iv, AES_ENCRYPT);

    // Free temp buffer
    free(data_to_encrypt);

    // Assigned encrypted payload to mme
    tx_encrypted_mme->encrypted_data = encrypted_data;

    return tx_encrypted_mme;
}

// Decrypt a CM_ENCRYPTED_PAYLOAD into a ETH frame
// Simpler version which doesn't support chained mmes (can be extended in the
// future if needed)
struct hpav_eth_frame *
hpav_decrypt_with_key(struct hpav_cm_encrypted_payload_ind *rx_encrypted_mme,
                      unsigned char decrypt_key[HPAV_AES_KEY_SIZE]) {
    // Decrypt payload and build a MME packet

    unsigned char *decrypted_payload = NULL;

    unsigned char aes_iv[HPAV_AES_KEY_SIZE];

    AES_KEY aes_key;

    struct hpav_eth_frame *new_eth_frame = NULL;

    unsigned char random_filler_size;

    if (rx_encrypted_mme == NULL) {
        return NULL;
    }

    // Buffer for decrypted payload
    decrypted_payload =
        (unsigned char *)malloc(rx_encrypted_mme->encrypted_data_length);

    // Init IV with IV from the message
    memcpy(aes_iv, rx_encrypted_mme->aes_iv, HPAV_AES_KEY_SIZE);

    // Decrypt payload with AES
    AES_set_decrypt_key(decrypt_key, HPAV_AES_KEY_SIZE * 8, &aes_key);
    AES_cbc_encrypt(rx_encrypted_mme->encrypted_data, decrypted_payload,
                    rx_encrypted_mme->encrypted_data_length, &aes_key, aes_iv,
                    AES_DECRYPT);

    // TODO : add CRC verification

    // Build new mme_packet
    new_eth_frame =
        (struct hpav_eth_frame *)malloc(sizeof(struct hpav_eth_frame));
    new_eth_frame->next = NULL;
    new_eth_frame->frame_size = rx_encrypted_mme->mme_length;
    // MME data is at the beginning of the decrypted payload right after the
    // randomfiller
    // Size of random filler at the end of the payload
    random_filler_size =
        *(decrypted_payload + rx_encrypted_mme->encrypted_data_length - 1);
    memcpy(new_eth_frame, decrypted_payload + random_filler_size,
           new_eth_frame->frame_size);

    free(decrypted_payload);

    return new_eth_frame;
}

struct hpav_eth_frame *
hpav_decrypt_with_dpw(struct hpav_cm_encrypted_payload_ind *rx_encrypted_mme,
                      const char *device_password) {
    // Compute DAK
    unsigned char dak[HPAV_AES_KEY_SIZE];
    hpav_generate_dak(device_password, dak);

    return hpav_decrypt_with_key(rx_encrypted_mme, dak);
}

struct hpav_eth_frame *
hpav_decrypt_with_nmk(struct hpav_cm_encrypted_payload_ind *rx_encrypted_mme,
                      unsigned char nmk[HPAV_AES_KEY_SIZE]) {
    return hpav_decrypt_with_key(rx_encrypted_mme, nmk);
}

// Decrypt a CM_ENCRYPTED_PAYLOAD when the payload is actually unencrypted
struct hpav_eth_frame *
hpav_decrypt_nokey(struct hpav_cm_encrypted_payload_ind *rx_encrypted_mme) {
    // Decrypt payload and build a MME packet

    struct hpav_eth_frame *new_eth_frame = NULL;

    unsigned char random_filler_size;

    if (rx_encrypted_mme == NULL) {
        return NULL;
    }

    // TODO : add CRC verification

    // Build new mme_packet
    new_eth_frame =
        (struct hpav_eth_frame *)malloc(sizeof(struct hpav_eth_frame));
    new_eth_frame->next = NULL;
    new_eth_frame->frame_size = rx_encrypted_mme->mme_length;
    // MME data is at the beginning of the payload right after the randomfiller
    // Size of random filler at the end of the payload
    random_filler_size = *(rx_encrypted_mme->encrypted_data +
                           rx_encrypted_mme->encrypted_data_length - 1);
    memcpy(new_eth_frame, rx_encrypted_mme->encrypted_data + random_filler_size,
           new_eth_frame->frame_size);

    return new_eth_frame;
}

// Decrypt based on value of PEKS
struct hpav_eth_frame *
hpav_decrypt(struct hpav_cm_encrypted_payload_ind *rx_encrypted_mme,
             const char *dpw, unsigned char nmk[HPAV_AES_KEY_SIZE]) {
    if (rx_encrypted_mme == NULL) {
        return NULL;
    }

    switch (rx_encrypted_mme->peks) {
    case HPAV_CM_ENCRYPTED_PAYLOAD_WITH_DAK:
        return hpav_decrypt_with_dpw(rx_encrypted_mme, dpw);
        break;
    case HPAV_CM_ENCRYPTED_PAYLOAD_WITH_NMK:
        return hpav_decrypt_with_nmk(rx_encrypted_mme, nmk);
        break;
    case HPAV_CM_ENCRYPTED_PAYLOAD_UNECRYPTED:
        return hpav_decrypt_nokey(rx_encrypted_mme);
        break;
    default:
        return NULL;
        break;
    }
}

// Encrypted payload. Implemented just for set_key for the moment.
// This works only for encryption with the DAK of the target device.
int hpav_cm_set_key_encrypted_sndrcv(
    struct hpav_chan *channel, unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE],
    struct hpav_cm_set_key_req *request, struct hpav_cm_set_key_cnf **response,
    unsigned int timeout_ms, unsigned int num_fragments,
    const char *device_password, struct hpav_error **error_stack) {
    // Strategy :
    // - build the MME packet like regular snd/rcv
    // - instead going to Ethernet, build a CM_ENCRYPTED_PAYLOAD MME
    // - then proceed to send the MME with regular send/receive
    // - decrypt the response
    // - build a CNF MME from the decrypted response

    /* MME packets */
    struct hpav_mme_packet *tx_mme_packets = NULL;
    struct hpav_mme_packet *rx_mme_packets = NULL;
    /* ETH frames (payload of the encrypted MME) */
    struct hpav_eth_frame *tx_frames = NULL;
    struct hpav_eth_frame *rx_frames = NULL;

    /* Encrypted packets */
    struct hpav_cm_encrypted_payload_ind *tx_encrypted_mme = NULL;
    struct hpav_cm_encrypted_payload_ind *rx_encrypted_mme = NULL;

    /* Result */
    int result = -1;
    /* Source MAC address */
    unsigned char src_mac_addr[ETH_MAC_ADDRESS_SIZE] = {0x00, 0x00, 0x00,
                                                        0x00, 0x00, 0x00};
    memcpy(src_mac_addr, channel->mac_addr, ETH_MAC_ADDRESS_SIZE);
    /* Init response */
    *response = NULL;

    /* Encode the mme into a buffer */
    tx_mme_packets =
        hpav_encode_cm_set_key_req(sta_mac_addr, src_mac_addr, request);

    /* Build the ETH frame (this is what CM_ENCRYPTED_PAYLOAD expects) */
    /* No Minimum size in this case, as the frame is not meant to be sent as is
     * onto the network */
    tx_frames = hpav_build_frames(tx_mme_packets, 0);

    /* Build a CM_ENCRYPTED_PAYLOAD.IND message with the encrypted data */
    tx_encrypted_mme = hpav_encrypt_with_dak(tx_frames, device_password);

    /* Send/receive the encrypted mme */
    /* In theory there should not be any fragmentation for this type of
     * encrypted MME */
    /* If this becomes necessary, we assume this would be done in this function
     * called */
    result = hpav_cm_encrypted_payload_sndrcv(
        channel, sta_mac_addr, tx_encrypted_mme, &rx_encrypted_mme, timeout_ms,
        num_fragments, error_stack);

    /* Decrypt received MME */
    /* Can be unecrypted or crypted with NMK */
    rx_frames =
        hpav_decrypt(rx_encrypted_mme, device_password, request->new_key);

    /* Build mme packet */
    rx_mme_packets = hpav_defrag_frames(rx_frames);

    /* Decode received MME */
    *response = hpav_decode_cm_set_key_cnf(rx_mme_packets);

    return result;
}

// Prepare a header for a standard MME
int hpav_setup_mme_header(unsigned short mme_type, unsigned int num_fragments,
                          unsigned int fragment_num,
                          unsigned fragment_sequence_number,
                          struct hpav_mme_header *header) {
    header->mmv = MME_HEADER_MMV_HPAV11;
    header->mmtype = mme_type;
    header->fmi_nf_fn = ((num_fragments << MME_HEADER_NUM_FRAGMENTS_SHIFT) &
                         MME_HEADER_NUM_FRAGMENTS_MASK) |
                        ((fragment_num << MME_HEADER_FRAGMENT_NUMBER_SHIFT) &
                         MME_HEADER_FRAGMENT_NUMBER_MASK);
    header->fmi_fmsn = fragment_sequence_number;
    return 0;
}

// Send a raw MME on the channel
// Caller prepares the MME header
int hpav_send_raw_mme(struct hpav_chan *channel,
                      unsigned char sta_mac_addr[ETH_MAC_ADDRESS_SIZE],
                      struct hpav_mme_header *header, unsigned char *mme_data,
                      unsigned int mme_data_size,
                      struct hpav_error **error_stack) {
    unsigned char *new_mme = NULL;
    unsigned int mme_size = sizeof(struct hpav_mme_header) + mme_data_size;
    struct hpav_mme_packet *new_packet =
        (struct hpav_mme_packet *)malloc(sizeof(struct hpav_mme_packet));
    struct hpav_mme_frame *mme_frame = NULL;
    struct hpav_eth_frame *tx_frames = NULL;
    struct hpav_eth_frame *current_frame = NULL;
    int result = -1;

    // First build a MME packet to feed common function calls
    new_mme = (unsigned char *)malloc(mme_size);
    mme_frame = (struct hpav_mme_frame *)new_mme;
    memcpy(&mme_frame->header, header, sizeof(struct hpav_mme_header));
    memcpy(&mme_frame->unknown_mme, mme_data, mme_data_size);
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
            // PCAP error
            char buffer[PCAP_ERRBUF_SIZE + 128];
            sprintf(buffer, "PCAP error code : %d, errbuf : %s", result,
                    pcap_geterr(channel->pcap_chan));
            hpav_add_error(error_stack, hpav_error_category_network,
                           hpav_error_module_core, HPAV_ERROR_PCAP_ERROR,
                           "pcap_sendpacket failed", buffer);
            return HPAV_ERROR_PCAP_ERROR;
        }
        current_frame = current_frame->next;
    }

    return HPAV_OK;
}

int hpav_sniff(struct hpav_chan *channel, hpav_sniff_callback callback,
               unsigned char *user_data, struct hpav_error **error_stack) {
    int result = -1;

    /* User data passed to pcap_dispatch() callback */
    callback_data_t cb_data;
    /* Hold compiled program */
    struct bpf_program fp;
    /* Init callback user data */
    memset(&cb_data, 0, sizeof(callback_data_t));
    /* Source MAC address */
    memcpy(cb_data.src_mac_addr, channel->mac_addr, ETH_MAC_ADDRESS_SIZE);

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

    do {
        result = pcap_dispatch(channel->pcap_chan, -1, rx_callback,
                               (u_char *)&cb_data);
        if (result > 0) {
            /* PCAP: number of  packets  processed  on  success */
            // Callback
            if (callback(user_data, cb_data.rx_frames) != 0) {
                // If callback doesn't return 0, stop sniffing. Allows limited
                // capture.
                break;
            }
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
            return HPAV_ERROR_PCAP_ERROR;
        } else /* (result == -2) */
        {
            /* PCAP: the loop terminated due to a call to pcap_breakloop()
             * before any packets were  processed */
            // We call the callback to give it a chance to exit.
            // Calback must check the value of frame pointer. It can be NULL in
            // this situation.
            if (callback(user_data, NULL) != 0) {
                break;
            }
        }

        /* Exit loop when callback sets the 'result' field of sniff_data_t
         * structure to a value different from 0.
         * Allows limited capture. */
    } while (!cb_data.stop);

    return HPAV_OK;
}
