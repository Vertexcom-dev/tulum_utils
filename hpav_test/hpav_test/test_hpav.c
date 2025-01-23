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
// Avoid unnecessary warnings with VC on strcpy (strcpy_s could be used, but is
// not portable)
#define _CRT_SECURE_NO_WARNINGS 1

// Test functions for Spidcom MMEs
#include "hpav_api.h"
#include "hpav_utils.h"
#include "util.h"
#include "test_hpav.h"
#include "exitcodes.h"

void dump_cm_set_key_cnf(struct hpav_cm_set_key_cnf *response) {
    int sta_num = 1;
    printf("--- Response from stations ---\n");
    if (response == NULL) {
        printf("No STA answered\n\n");
        return;
    }

    while (response != NULL) {
        char buffer[64];
        printf("Station %d :\n", sta_num);
        printf("MAC address                                           : %s\n",
               hpav_mactos(response->sta_mac_addr, buffer));
        printf("Result                                                : %d\n",
               response->result);
        printf("My Nonce                                              : %d\n",
               response->my_nonce);
        printf("Your Nonce                                            : %d\n",
               response->your_nonce);
        printf("Protocol ID                                           : %d\n",
               response->pid);
        printf("Protocol run number                                   : %d\n",
               response->prn);
        printf("Protocol message number                               : %d\n",
               response->pmn);
        printf("CCO capability                                        : %d\n",
               response->cco_cap);

        printf("\n");
        sta_num++;
        response = response->next;
    }
}

int test_mme_cm_set_key_req(hpav_chan_t *channel, int argc, char *argv[]) {
    struct hpav_cm_set_key_req mme_sent;
    struct hpav_cm_set_key_cnf *response = NULL;
    // Broadcast by default
    unsigned char dest_mac[ETH_MAC_ADDRESS_SIZE] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    struct hpav_error *error_stack = NULL;
    unsigned int key_type;
    unsigned int my_nonce;
    unsigned int your_nonce;
    unsigned int pid;
    unsigned int prn;
    unsigned int pmn;
    unsigned int cco_cap;
    unsigned char nid[HPAV_NID_SIZE];
    unsigned int new_eks;
    unsigned char new_key[HPAV_MD5SUM_SIZE];
    int rv = EXIT_SUCCESS;

    // Parameters
    if (argc < 11) {
        printf("Mandatory parameters : sta_mac_address key_type my_nonce "
               "your_nonce pid prn pmn cco_cap nid new_eks new_key "
               "[device_password]\n");
        printf("sta_mac_address : MAC address of the destination STA\n");
        printf("key_type : key type (1 for NMK)\n");
        printf("my_nonce : random number (unsigned 32-bit integer)\n");
        printf("your_nonce : random number (unsigned 32-bit integer)\n");
        printf("pid : protocol ID\n");
        printf("prn : protocol run number\n");
        printf("pmn : protocol message number\n");
        printf("cco_cap : CCo capability\n");
        printf("nid : NID of the network being queried\n");
        printf("new_eks : new EKS or new payload EKS\n");
        printf(
            "new_key : new key (16 bytes written as 32 hexadecimal digits))\n");
        printf("device_password : if present DAK encrypt the MME \n");
        return EXIT_USAGE;
    }

    if (argc > 0) {
        if (!hpav_stomac(argv[0], dest_mac)) {
            printf("An error occurred. Input mac value is in valid format...\n");
            return EXIT_USAGE;
        }
    }

    key_type = atoi(argv[1]);
    sscanf(argv[2], "%u", &my_nonce);
    sscanf(argv[3], "%u", &your_nonce);
    pid = atoi(argv[4]);
    prn = atoi(argv[5]);
    pmn = atoi(argv[6]);
    cco_cap = atoi(argv[7]);
    hpav_stonid(argv[8], nid);
    new_eks = atoi(argv[9]);
    hpav_stomd5sum(argv[10], new_key);

    // Parameters
    mme_sent.key_type = key_type;
    mme_sent.my_nonce = my_nonce;
    mme_sent.your_nonce = your_nonce;
    mme_sent.pid = pid;
    mme_sent.prn = prn;
    mme_sent.pmn = pmn;
    mme_sent.cco_cap = cco_cap;
    memcpy(mme_sent.nid, nid, HPAV_NID_SIZE);
    mme_sent.new_eks = new_eks;
    memcpy(mme_sent.new_key, new_key, HPAV_MD5SUM_SIZE);
    // Sending MME on the channel
    if (argc >= 12) {
        printf("Sending encrypted CM_SET_KEY.REQ "
               "(CM_ENCRYPTED_PAYLOAD.IND) on the channel\n");
        rv = hpav_cm_set_key_encrypted_sndrcv(channel, dest_mac, &mme_sent,
                                              &response, 1000, 1, argv[11],
                                              &error_stack);
    } else {
        printf("Sending CM_SET_KEY.REQ on the channel\n");
        rv = hpav_cm_set_key_sndrcv(channel, dest_mac, &mme_sent, &response,
                                    1000, 1, &error_stack);
    }
    if (rv != HPAV_OK) {
        printf("An error occurred. Dumping error stack...\n");
        hpav_dump_error_stack(error_stack);
        hpav_free_error_stack(&error_stack);
        rv = EXIT_FAILURE;
    } else {
        // Dump response
        dump_cm_set_key_cnf(response);
        if (response == NULL)
            rv = EXIT_NO_RESPONSE;
    }
    // Free response
    hpav_free_cm_set_key_cnf(response);
    return rv;
}

void dump_cm_amp_map_cnf(struct hpav_cm_amp_map_cnf *response) {
    int sta_num = 1;
    printf("--- Response from stations ---\n");
    if (response == NULL) {
        printf("No STA answered\n\n");
        return;
    }

    while (response != NULL) {
        char buffer[64];
        printf("Station %d :\n", sta_num);
        printf("MAC address                                           : %s\n",
               hpav_mactos(response->sta_mac_addr, buffer));
        printf("Response Type                                         : %d\n",
               response->res_type);
        printf("\n");
        sta_num++;
        response = response->next;
    }
}

int test_mme_cm_amp_map_req(hpav_chan_t *channel, int argc, char *argv[]) {
    struct hpav_error *error_stack = NULL;
    struct hpav_cm_amp_map_req mme_sent;
    struct hpav_cm_amp_map_cnf *response = NULL;
    // Broadcast by default
    unsigned char dest_mac[ETH_MAC_ADDRESS_SIZE] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    int map_ktr = 0;
    int amlen = 0;
    FILE *fp;
    int data_count;
    int am_data[3600];
    char buf[2];
    int rv = EXIT_SUCCESS;

    // parameters
    if (argc < 2) {
        printf("Mandatory parameters : sta_mac_address AMLEN AMDATA\n");
        printf("sta_mac_address : MAC address of the destination STA\n");
        printf("AMLEN : Number of amplitude map data entries\n");
        printf("AMDATA : Amplitude Map Data (.txt file input)\n");
        return EXIT_USAGE;
    }

    if (argc > 0) {
        if (!hpav_stomac(argv[0], dest_mac)) {
            printf("An error occurred. Input mac value is in valid format...\n");
            return EXIT_USAGE;
        }
    }

    // parser parameters to am_data array
    amlen = atoi(argv[1]);
    if ((amlen > 3528) || (amlen < 0)) {
        printf("AMLEN must less than 3528 and bigger than 0\n");
        return -1;
    }

    fp = fopen(argv[2], "r");
    if (!fp) {
        printf("Fail to open AMDATA file\n");
        return -1;
    }

    for (data_count = 0; data_count < amlen; data_count++) {
        fseek(fp, (data_count * 3 + data_count), SEEK_SET);
        fread(buf, sizeof(char), 2, fp);
        am_data[data_count] = atoi(buf);
        if ((am_data[data_count] < 0) || (am_data[data_count] > 16)) {
            printf("AM_DATA error, [%d]=%d\n", data_count, am_data[data_count]);
            fclose(fp);
            return -1;
        }
    }
    fclose(fp);

    // Sending MME on the channel
    printf("Sending CM_AMP_MAP.REQ on the channel\n");

    mme_sent.map_length = amlen;

    for (map_ktr = 0; map_ktr < (mme_sent.map_length / 2 +
                                 mme_sent.map_length % 2);
         map_ktr++)
        mme_sent.map_data[map_ktr] =
            am_data[map_ktr * 2] + (am_data[map_ktr * 2 + 1] << 4);

    rv = hpav_cm_amp_map_sndrcv(channel, dest_mac, &mme_sent,
                                &response, 1000, 1, &error_stack);
    if (rv != HPAV_OK) {
        printf("An error occurred. Dumping error stack...\n");
        hpav_dump_error_stack(error_stack);
        hpav_free_error_stack(&error_stack);
        rv = EXIT_FAILURE;
    } else {
        // Dump response
        dump_cm_amp_map_cnf(response);
        if (response == NULL)
            rv = EXIT_NO_RESPONSE;
    }
    // Free response
    hpav_free_cm_amp_map_cnf(response);
    return rv;
}
