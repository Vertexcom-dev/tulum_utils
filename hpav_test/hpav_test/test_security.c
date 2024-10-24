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
#include "test_security.h"
#include "hpav_api.h"
#include "hpav_utils.h"
#include "hpav_mme.h"

int test_secu_gen_nmk(int argc, char *argv[]) {
    // First argument is network password to generate NMK from
    // Argument count is checked by the caller

    char buffer[128];
    unsigned char nmk[HPAV_AES_KEY_SIZE];
    hpav_generate_nmk(argv[0], nmk);

    printf("Generated NMK from password : <%s>\n", argv[0]);
    printf("NMK                         : %s\n", hpav_aeskeytos(nmk, buffer));
    return 0;
}

int test_secu_gen_dak(int argc, char *argv[]) {
    // First argument is device password to generate DAK from
    // Argument count is checked by the caller

    char buffer[128];
    unsigned char dak[HPAV_AES_KEY_SIZE];
    hpav_generate_dak(argv[0], dak);

    printf("Generated DAK from password : <%s>\n", argv[0]);
    printf("DAK                         : %s\n", hpav_aeskeytos(dak, buffer));
    return 0;
}

int test_secu_gen_nid(int argc, char *argv[]) {
    // First argument is NMK to generate NID from
    // Argument count is checked by the caller

    // Input is a NMK
    char buffer[128];
    unsigned char nid[HPAV_NID_SIZE];
    unsigned char nmk[HPAV_AES_KEY_SIZE];
    unsigned char security_level = 0;
    hpav_stomd5sum(argv[0], nmk);

    if (argc > 1) {
        security_level = atoi(argv[1]);
    }

    hpav_generate_nid(nmk, security_level, nid);
    printf("Generated NID from NMK      : <%s>\n", argv[0]);
    printf("NID                         : %s\n", hpav_nidtos(nid, buffer));
    return 0;
}

// Test encryption of cm_set_key MME
int test_secu_encrypt(int argc, char *argv[]) {
    // HPAV specification gives an example of set_key encryption. See Table 13-5
    // Validated by adjusting the size and content of random and padding bytes
    // in hpav_encrypt_with_dak
    // (see //TESTING commented lines including avln_status to match the value
    // in the spec)
    struct hpav_eth_frame *tx_eth_frame = NULL;
    struct hpav_mme_packet tx_packet;
    unsigned char src_mac_addr[ETH_MAC_ADDRESS_SIZE] = {0x00, 0x46, 0x47,
                                                        0x48, 0x49, 0x50};
    unsigned char dst_mac_addr[ETH_MAC_ADDRESS_SIZE] = {0x00, 0x31, 0x32,
                                                        0x33, 0x34, 0x35};
    unsigned char nid[HPAV_NID_SIZE] = {0x02, 0x6B, 0xCB, 0xA5,
                                        0x35, 0x4E, 0x18};
    unsigned char nmk[HPAV_AES_KEY_SIZE] = {0xB5, 0x93, 0x19, 0xD7, 0xE8, 0x15,
                                            0x7B, 0xA0, 0x01, 0xB0, 0x18, 0x66,
                                            0x9C, 0xCE, 0xE3, 0x0D};
    struct hpav_mme_header mme_header;
    struct hpav_cm_set_key_req set_key_request;
    struct hpav_cm_encrypted_payload_ind *encrypted_mme = NULL;
    // MME data is a CM_SET_KEY
    mme_header.mmtype = MMTYPE_CM_SET_KEY_REQ;
    mme_header.mmv = MME_HEADER_MMV_HPAV11;
    mme_header.fmi_fmsn = 0;
    mme_header.fmi_nf_fn = 0;

    set_key_request.key_type = 1;
    set_key_request.my_nonce = 0x33221100;
    set_key_request.your_nonce = 0x11223344;
    set_key_request.pid = 2;
    set_key_request.prn = 0x372D;
    set_key_request.pmn = 3;
    set_key_request.cco_cap = 2;
    memcpy(set_key_request.nid, nid, HPAV_NID_SIZE);
    set_key_request.new_eks = 1;
    memcpy(set_key_request.new_key, nmk, HPAV_AES_KEY_SIZE);

    // Build packet
    tx_packet.data_size =
        sizeof(struct hpav_mme_header) + sizeof(struct hpav_cm_set_key_req);
    tx_packet.data = malloc(tx_packet.data_size);
    memcpy(tx_packet.data, &mme_header, sizeof(struct hpav_mme_header));
    memcpy(tx_packet.data + sizeof(struct hpav_mme_header), &set_key_request,
           sizeof(struct hpav_cm_set_key_req));
    memcpy(tx_packet.src_mac_addr, src_mac_addr, ETH_MAC_ADDRESS_SIZE);
    memcpy(tx_packet.dst_mac_addr, dst_mac_addr, ETH_MAC_ADDRESS_SIZE);
    tx_packet.next = NULL;

    tx_eth_frame = hpav_build_frames(&tx_packet, 0);

    encrypted_mme = hpav_encrypt_with_dak(tx_eth_frame, "DAK_Password");

    // Dump result to compare to specification
    hpav_dump_bitfield(encrypted_mme->encrypted_data,
                       encrypted_mme->encrypted_data_length);

    // Free data
    hpav_free_eth_frames(tx_eth_frame);
    hpav_free_cm_encrypted_payload_ind(encrypted_mme);
    free(tx_packet.data);

    return 0;
}
