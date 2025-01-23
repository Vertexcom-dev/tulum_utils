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
#include "test_nvram.h"
#include "hpav_api.h"
#include "hpav_mtk_api.h"
#include "hpav_utils.h"
#include "test_mtk.h"
#include "exitcodes.h"
#if defined(__linux__)
#include <arpa/inet.h>
#endif

int test_nvram_read(hpav_chan_t *channel, int argc, char *argv[]) {
    struct hpav_error *error_stack = NULL;
    struct hpav_mtk_vs_get_nvram_req mme_sent;
    struct hpav_mtk_vs_get_nvram_cnf *response = NULL;
    // Broadcast by default
    unsigned char dest_mac[ETH_MAC_ADDRESS_SIZE] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    int rv = EXIT_SUCCESS;

    if (argc < 2) {
        printf("Usage : hpav_test nvram read interface mac output_file\n");
        return EXIT_USAGE;
    }
    if (!hpav_stomac(argv[0], dest_mac)) {
        printf("An error occurred. Input mac value is in valid format...\n");
        return EXIT_USAGE;
    }

    /* REQ parameters (block_index): the size of nvram is not bigger
     * than one block now */
    mme_sent.index = (unsigned char)0;
    // Sending MME on the channel
    rv = hpav_mtk_vs_get_nvram_sndrcv(channel, dest_mac,
                                      &mme_sent, &response,
                                      1000, 0, &error_stack);
    if (rv != HPAV_OK) {
        printf("An error occurred. Dumping error stack...\n");
        hpav_dump_error_stack(error_stack);
        hpav_free_error_stack(&error_stack);
        rv = EXIT_FAILURE;
    } else {
        int sta_num = 1, i, j;
        if (response != NULL) {
            char buffer[64];
            printf("Station %d :\n", sta_num);
            printf("MAC address                                    "
                   "       : %s\n",
                   hpav_mactos(response->sta_mac_addr, buffer));
            printf("Result                                         "
                   "       : %s\n",
                   (response->result == 0)
                       ? "SUCCESS"
                       : ((response->result == 1) ? "FAILURE"
                                                  : "BAD_INDEX"));
            printf("Index                                          "
                   "       : %d\n",
                   response->index);
            printf("Nvram size                                     "
                   "       : %d\n",
                   (response->nvram_size));
            printf("NVRAM contents                                 "
                   "       : \n");

            if (response->result == 0) {
                for (i = 0; i < 32; i++) {
                    for (j = 0; j < 32; j++)
                        printf("%02x ", response->data[32 * i + j]);
                    printf("\n");
                }
            } else {
                printf("No content.\n");
            }

            printf("\n");
            // Write nvram data into output_file
            FILE *nvram = NULL;
            nvram = fopen(argv[1], "w");
            if (NULL == nvram) {
                printf("error while creating file %s\n", argv[1]);
                return -1;
            }
            fwrite(&response->data, 1, response->nvram_size, nvram);
            fclose(nvram);

        } else {
            printf("No response. Get nvram fails.\n");
            rv = EXIT_NO_RESPONSE;
        }
    }
    // Free response
    hpav_free_mtk_vs_get_nvram_cnf(response);
    return rv;
}

int test_nvram_write(hpav_chan_t *channel, int argc, char *argv[]) {
    struct hpav_error *error_stack = NULL;
    unsigned char block_data[MTK_NVRAM_BLOCK_SIZE];
    FILE *nvram = NULL;
    unsigned short nvram_size = MTK_NVRAM_BLOCK_SIZE;
    int block_index = 0;
    struct hpav_mtk_vs_set_nvram_req mme_sent;
    struct hpav_mtk_vs_set_nvram_cnf *response = NULL;
    // Broadcast by default
    unsigned char dest_mac[ETH_MAC_ADDRESS_SIZE] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    int rv = EXIT_SUCCESS;

    if (argc < 2) {
        printf("Usage : hpav_test nvram write interface mac input_file\n");
        return EXIT_USAGE;
    }
    if (!hpav_stomac(argv[0], dest_mac)) {
        printf("An error occurred. Input mac value is in valid format...\n");
        return EXIT_USAGE;
    }

    nvram = fopen(argv[1], "r");
    if (NULL == nvram) {
        printf("error while opening file %s\n", argv[1]);
        return -1;
    }

    fseek(nvram, 0, SEEK_END);
    nvram_size = (unsigned short)ftell(nvram);
    rewind(nvram);

    memset(block_data, 0, MTK_NVRAM_BLOCK_SIZE);
    if (1 != fread(block_data, nvram_size, 1, nvram)) {
        printf("error while reading file %s\n", argv[1]);
        return -1;
    }

    fclose(nvram);
    nvram = NULL;

    // Parameters
    mme_sent.block_index = block_index;
    mme_sent.nvram_size = nvram_size;
    if (xorchecksum(block_data, nvram_size, &mme_sent.checksum) ==
        -1) {
        printf("Calculate checksum error!\n");
        return -1;
    }
    // handle Endian problem
    mme_sent.checksum = htonl(mme_sent.checksum);

    memcpy(mme_sent.data, block_data, nvram_size);
    // Sending MME on the channel
    rv = hpav_mtk_vs_set_nvram_sndrcv(channel, dest_mac, &mme_sent, &response,
                                      1000, 0, &error_stack);
    if (rv != HPAV_OK) {
        printf("An error occurred. Dumping error stack...\n");
        hpav_dump_error_stack(error_stack);
        hpav_free_error_stack(&error_stack);
        rv = EXIT_FAILURE;
    } else {
        if (response == NULL) {
            printf("Failed to write nvram.\n");
            rv = EXIT_FAILURE;
        } else {
            if (response->result == 0)
                printf("Write nvram successfully.\n");
        }
    }
    hpav_free_mtk_vs_set_nvram_cnf(response);
    return rv;
}

int test_nvram_parse(int argc, char *argv[]) {
    if (argc != 1) {
        printf("Usage: hpav_test nvram parse input_file\n");
        return EXIT_USAGE;
    }

    FILE *nvram = NULL;
    int nvram_read_size = sizeof(nvram_t);
    nvram_t nvram_data;

    nvram = fopen(argv[0], "r");
    if (NULL == nvram) {
        printf("error while opening file %s\n", argv[0]);
        return -1;
    }

    if (1 != fread(&nvram_data, nvram_read_size, 1, nvram)) {
        printf("error while reading file %s\n", argv[0]);
        return -1;
    }

    int i;
    printf("mac\t\t: ");
    for (i = 0; i < 6; i++) {
        printf("%02x", nvram_data.mac[i]);
        if (i != 5)
            printf(":");
    }
    printf("\n");
    fclose(nvram);
    nvram = NULL;
    return 0;
}

int test_nvram_modify(int argc, char *argv[]) {
    if (argc < 3 || (argc & 1) == 0) {
        printf("Usage : hpav_test nvram modify input_file mac "
               "xx:xx:xx:xx:xx:xx\n");
        return EXIT_USAGE;
    }

    FILE *nvram = NULL;
    int nvram_read_size = sizeof(nvram_t);
    nvram_t nvram_data;
    nvram = fopen(argv[0], "r");
    if (NULL == nvram) {
        printf("error while opening file %s\n", argv[0]);
        return -1;
    }

    if (1 != fread(&nvram_data, nvram_read_size, 1, nvram)) {
        printf("error while reading file %s\n", argv[0]);
        return -1;
    }

    fclose(nvram);
    nvram_t modify_data;
    memcpy(&modify_data, &nvram_data, sizeof(modify_data));

    int i;
    if (strcmp(argv[1], "mac") == 0) {
        int mac_int[6];
        sscanf(argv[2], "%x:%x:%x:%x:%x:%x", &mac_int[0], &mac_int[1],
               &mac_int[2], &mac_int[3], &mac_int[4], &mac_int[5]);
        unsigned char *mac_data;
        mac_data = malloc(6);
        for (i = 0; i < 6; i++) {
            mac_data[i] = (unsigned char)mac_int[i];
        }
        memcpy(modify_data.mac, mac_data, sizeof(modify_data.mac));
    } else {
        printf("Usage : hpav_test nvram modify input_file mac "
               "xx:xx:xx:xx:xx:xx\n");
        return EXIT_USAGE;
    }

    nvram = fopen(argv[0], "w");
    if (NULL == nvram) {
        printf("error while opening file %s\n", argv[0]);
        return -1;
    }

    fwrite(&modify_data, sizeof(modify_data), 1, nvram);
    fclose(nvram);

    nvram = NULL;
    return 0;
}
