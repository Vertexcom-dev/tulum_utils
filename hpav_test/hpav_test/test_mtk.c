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
#include "test_mtk.h"
#include "hpav_api.h"
#include "hpav_utils.h"
#include "hpav_mtk_api.h"
#include "hpav_mtk_field.h"
#include "openssl_md5.h"
#include "util.h"
#include "stdbool.h"
#include "stdarg.h"

#ifdef WIN32
#include "windows.h"
#else
#include "unistd.h"
#include <netinet/in.h>
#endif

static bool silence = false;

void test_mme_mtk_printf_silence(void) { silence = true; }

static void test_mtk_printf(const char *format, ...) {
    if (silence)
        return;
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

unsigned int hpab_strtoui(char *string) {
    if (!strncmp(string, "0x", 2))
        return strtoul(string, NULL, 16);
    else
        return strtoul(string, NULL, 10);
}

void dump_mtk_vs_set_nvram_cnf(struct hpav_mtk_vs_set_nvram_cnf *response) {
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
        printf("\n");
        sta_num++;
        response = response->next;
    }
}
int test_mme_mtk_vs_set_nvram_req(int interface_num_to_open, int argc,
                                  char *argv[]) {
    struct hpav_if *interfaces = NULL;
    struct hpav_error *error_stack = NULL;
    unsigned int block_index;
    unsigned char block_data[MTK_NVRAM_BLOCK_SIZE];
    FILE *nvram = NULL;
    unsigned short nvram_size = MTK_NVRAM_BLOCK_SIZE;
    long nvram_read_size = 0;
    unsigned int nvram_block_size_max = 0;
    if (argc < 3) {
        printf("Mandatory parameters : sta_mac_address block_index filename\n");
        printf("sta_mac_address : MAC address of the destination STA\n");
        printf("block_index : index of the NVRAM block to write\n");
        printf("filename : binary file with data to write (gets the block at "
               "given index from it)\n");
        return -1;
    }
    // Get parameters
    block_index = atoi(argv[1]);

    // Open file
    nvram = fopen(argv[2], "r");
    if (NULL == nvram) {
        printf("error while opening file %s\n", argv[2]);
        return -1;
    }

    // Obtain file size
    fseek(nvram, 0, SEEK_END);
    nvram_size = (unsigned short)ftell(nvram);

    rewind(nvram);

    // Check if the index of NVRAM block to write larger than NVRAM size
    nvram_block_size_max = nvram_size / MTK_NVRAM_BLOCK_SIZE;
    if (block_index > nvram_block_size_max) {
        printf("error: your nvram size is %d, but the index of NVRAM block you "
               "want to write is %d",
               nvram_size, block_index);
        fclose(nvram);
        return -1;
    }

    fseek(nvram, block_index * 1024, SEEK_SET);
    // File reading
    memset(block_data, 0, MTK_NVRAM_BLOCK_SIZE);

    // based on the index of NVRAM block to write, you should check how many
    // size to read
    if (block_index == nvram_block_size_max) {
        nvram_read_size =
            nvram_size - (nvram_block_size_max * MTK_NVRAM_BLOCK_SIZE);
    } else {
        nvram_read_size = MTK_NVRAM_BLOCK_SIZE;
    }

    if (1 != fread(block_data, nvram_read_size, 1, nvram)) {
        printf("error while reading file %s\n", argv[2]);
        return -1;
    }

    // Close file
    fclose(nvram);
    nvram = NULL;

    // Get list of interfaces from libhpav
    if (hpav_get_interfaces(&interfaces, &error_stack) != HPAV_OK) {
        printf("An error occured. Dumping error stack...\n");
        hpav_dump_error_stack(error_stack);
        hpav_free_error_stack(&error_stack);
        return -1;
    }

    if (interfaces != NULL) {
        struct hpav_if *interface_to_open = NULL;
        // Get interface
        interface_to_open =
            hpav_get_interface_by_index(interfaces, interface_num_to_open);

        // Check if an interface with this number was found
        if (interface_to_open != NULL) {
            struct hpav_chan *current_chan = NULL;
            // Open the interface
            printf("Opening interface %d : %s (%s)\n", interface_num_to_open,
                   interface_to_open->name,
                   (interface_to_open->description != NULL
                        ? interface_to_open->description
                        : "no description"));
            current_chan = hpav_open_channel(interface_to_open, &error_stack);
            if (current_chan != NULL) {
                int result = -1;
                struct hpav_mtk_vs_set_nvram_req mme_sent;
                struct hpav_mtk_vs_set_nvram_cnf *response;
                // Broadcast by default
                unsigned char dest_mac[ETH_MAC_ADDRESS_SIZE] = {
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
                if (argc > 0) {
                    if (!hpav_stomac(argv[0], dest_mac)) {
                        printf("An error occured. Input mac value is in valid format...\n");
                        return -1;
                    }
                }

                printf("Interface successfully opened\n");
                // Parameters
                mme_sent.block_index = block_index;
                mme_sent.nvram_size = nvram_size;
                if (xorchecksum(&block_data, nvram_read_size,
                                &mme_sent.checksum) == -1) {
                    printf("Calculate checksum error!\n");
                    return -1;
                }
                // handle Endian problem
                mme_sent.checksum = htonl(mme_sent.checksum);

                memcpy(mme_sent.data, block_data, nvram_read_size);
                // Sending MME on the channel
                printf("Sending Mstar VS_SET_NVRAM.REQ on the channel\n");
                result = hpav_mtk_vs_set_nvram_sndrcv(current_chan, dest_mac,
                                                      &mme_sent, &response,
                                                      1000, 0, &error_stack);
                if (result != HPAV_OK) {
                    printf("An error occured. Dumping error stack...\n");
                    hpav_dump_error_stack(error_stack);
                    hpav_free_error_stack(&error_stack);
                } else {
                    // Dump response
                    dump_mtk_vs_set_nvram_cnf(response);
                }
                // Free response
                hpav_free_mtk_vs_set_nvram_cnf(response);
                // Close channel
                hpav_close_channel(current_chan);
                printf("Interface closed\n");
            } else {
                printf("Error while opening the interface\n");
                hpav_dump_error_stack(error_stack);
                hpav_free_error_stack(&error_stack);
            }
        } else {
            unsigned int num_interfaces =
                hpav_get_number_of_interfaces(interfaces);
            printf("Interface number %d not found (0-%d available)\n",
                   interface_num_to_open, (num_interfaces - 1));
        }
        // Free list of interfaces
        hpav_free_interfaces(interfaces);
    } else {
        printf("No interface available\n");
    }
    return 0;
}

void dump_mtk_vs_get_version_cnf(struct hpav_mtk_vs_get_version_cnf *response) {
    int sta_num = 1;
    printf("--- Response from stations ---\n");
    if (response == NULL) {
        printf("No STA answered\n\n");
        return;
    }

    while (response != NULL) {
        char buffer[65];
        memset(buffer, 0, 65);
        printf("Station %d :\n", sta_num);
        printf("MAC address                                           : %s\n",
               hpav_mactos(response->sta_mac_addr, buffer));
        printf("Result                                                : %d\n",
               response->result);
        printf("Device ID                                             : %d\n",
               response->device_id);
        printf("Current image index                                   : %d\n",
               response->image_index);
        memset(buffer, 0, 65);
        memcpy(buffer, response->applicative_version, 16);
        printf("Current applicative layer version                     : %s\n",
               buffer);
        memset(buffer, 0, 65);
        memcpy(buffer, response->av_stack_version, 64);
        printf("Current AV stack version                              : %s\n",
               buffer);
        memset(buffer, 0, 65);
        memcpy(buffer, response->bootloader_version, 64);
        printf("Current bootloader version                            : %s\n",
               buffer);
        memset(buffer, 0, 65);
        memcpy(buffer, response->alternate_applicative_version, 16);
        printf("Alternate applicative layer version                   : %s\n",
               buffer);
        printf("\n");
        sta_num++;
        response = response->next;
    }
}
int test_mme_mtk_vs_get_version_req(int interface_num_to_open, int argc,
                                    char *argv[]) {
    struct hpav_if *interfaces = NULL;
    struct hpav_error *error_stack = NULL;
    // Get list of interfaces from libhpav
    if (hpav_get_interfaces(&interfaces, &error_stack) != HPAV_OK) {
        printf("An error occured. Dumping error stack...\n");
        hpav_dump_error_stack(error_stack);
        hpav_free_error_stack(&error_stack);
        return -1;
    }

    if (interfaces != NULL) {
        struct hpav_if *interface_to_open = NULL;
        // Get interface
        interface_to_open =
            hpav_get_interface_by_index(interfaces, interface_num_to_open);

        // Check if an interface with this number was found
        if (interface_to_open != NULL) {
            struct hpav_chan *current_chan = NULL;
            // Open the interface
            printf("Opening interface %d : %s (%s)\n", interface_num_to_open,
                   interface_to_open->name,
                   (interface_to_open->description != NULL
                        ? interface_to_open->description
                        : "no description"));
            current_chan = hpav_open_channel(interface_to_open, &error_stack);
            if (current_chan != NULL) {
                int result = -1;
                struct hpav_mtk_vs_get_version_req mme_sent;
                struct hpav_mtk_vs_get_version_cnf *response;
                // Broadcast by default
                unsigned char dest_mac[ETH_MAC_ADDRESS_SIZE] = {
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
                if (argc > 0) {
                    if (!hpav_stomac(argv[0], dest_mac)) {
                        printf("An error occured. Input mac value is in valid format...\n");
                        return -1;
                    }
                }

                printf("Interface successfully opened\n");
                // Sending MME on the channel
                printf("Sending Mstar VS_GET_VERSION.REQ on the channel\n");
                result = hpav_mtk_vs_get_version_sndrcv(current_chan, dest_mac,
                                                        &mme_sent, &response,
                                                        1000, 0, &error_stack);
                if (result != HPAV_OK) {
                    printf("An error occured. Dumping error stack...\n");
                    hpav_dump_error_stack(error_stack);
                    hpav_free_error_stack(&error_stack);
                } else {
                    // Dump response
                    dump_mtk_vs_get_version_cnf(response);
                }
                // Free response
                hpav_free_mtk_vs_get_version_cnf(response);
                // Close channel
                hpav_close_channel(current_chan);
                printf("Interface closed\n");
            } else {
                printf("Error while opening the interface\n");
                hpav_dump_error_stack(error_stack);
                hpav_free_error_stack(&error_stack);
            }
        } else {
            unsigned int num_interfaces =
                hpav_get_number_of_interfaces(interfaces);
            printf("Interface number %d not found (0-%d available)\n",
                   interface_num_to_open, (num_interfaces - 1));
        }
        // Free list of interfaces
        hpav_free_interfaces(interfaces);
    } else {
        printf("No interface available\n");
    }
    return 0;
}

void dump_mtk_vs_reset_cnf(struct hpav_mtk_vs_reset_cnf *response) {
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
        printf("\n");
        sta_num++;
        response = response->next;
    }
}
int test_mme_mtk_vs_reset_req(int interface_num_to_open, int argc,
                              char *argv[]) {
    struct hpav_if *interfaces = NULL;
    struct hpav_error *error_stack = NULL;
    // Get list of interfaces from libhpav
    if (hpav_get_interfaces(&interfaces, &error_stack) != HPAV_OK) {
        printf("An error occured. Dumping error stack...\n");
        hpav_dump_error_stack(error_stack);
        hpav_free_error_stack(&error_stack);
        return -1;
    }

    if (interfaces != NULL) {
        struct hpav_if *interface_to_open = NULL;
        // Get interface
        interface_to_open =
            hpav_get_interface_by_index(interfaces, interface_num_to_open);

        // Check if an interface with this number was found
        if (interface_to_open != NULL) {
            struct hpav_chan *current_chan = NULL;
            // Open the interface
            printf("Opening interface %d : %s (%s)\n", interface_num_to_open,
                   interface_to_open->name,
                   (interface_to_open->description != NULL
                        ? interface_to_open->description
                        : "no description"));
            current_chan = hpav_open_channel(interface_to_open, &error_stack);
            if (current_chan != NULL) {
                int result = -1;
                struct hpav_mtk_vs_reset_req mme_sent;
                struct hpav_mtk_vs_reset_cnf *response;
                // Broadcast by default
                unsigned char dest_mac[ETH_MAC_ADDRESS_SIZE] = {
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
                if (argc > 0) {
                    if (!hpav_stomac(argv[0], dest_mac)) {
                        printf("An error occured. Input mac value is in valid format...\n");
                        return -1;
                    }
                }

                printf("Interface successfully opened\n");
                // Sending MME on the channel
                printf("Sending Mstar VS_RESET.REQ on the channel\n");
                result =
                    hpav_mtk_vs_reset_sndrcv(current_chan, dest_mac, &mme_sent,
                                             &response, 1000, 0, &error_stack);
                if (result != HPAV_OK) {
                    printf("An error occured. Dumping error stack...\n");
                    hpav_dump_error_stack(error_stack);
                    hpav_free_error_stack(&error_stack);
                } else {
                    // Dump response
                    dump_mtk_vs_reset_cnf(response);
                }
                // Free response
                hpav_free_mtk_vs_reset_cnf(response);
                // Close channel
                hpav_close_channel(current_chan);
                printf("Interface closed\n");
            } else {
                printf("Error while opening the interface\n");
                hpav_dump_error_stack(error_stack);
                hpav_free_error_stack(&error_stack);
            }
        } else {
            unsigned int num_interfaces =
                hpav_get_number_of_interfaces(interfaces);
            printf("Interface number %d not found (0-%d available)\n",
                   interface_num_to_open, (num_interfaces - 1));
        }
        // Free list of interfaces
        hpav_free_interfaces(interfaces);
    } else {
        printf("No interface available\n");
    }
    return 0;
}
int test_mme_mtk_vs_reset_ind(int interface_num_to_open, int argc,
                              char *argv[]) {
    struct hpav_if *interfaces = NULL;
    struct hpav_error *error_stack = NULL;
    // Get list of interfaces from libhpav
    if (hpav_get_interfaces(&interfaces, &error_stack) != HPAV_OK) {
        printf("An error occured. Dumping error stack...\n");
        hpav_dump_error_stack(error_stack);
        hpav_free_error_stack(&error_stack);
        return -1;
    }

    if (interfaces != NULL) {
        struct hpav_if *interface_to_open = NULL;
        // Get interface
        interface_to_open =
            hpav_get_interface_by_index(interfaces, interface_num_to_open);

        // Check if an interface with this number was found
        if (interface_to_open != NULL) {
            struct hpav_chan *current_chan = NULL;
            // Open the interface
            printf("Opening interface %d : %s (%s)\n", interface_num_to_open,
                   interface_to_open->name,
                   (interface_to_open->description != NULL
                        ? interface_to_open->description
                        : "no description"));
            current_chan = hpav_open_channel(interface_to_open, &error_stack);
            if (current_chan != NULL) {
                int result = -1;
                struct hpav_mtk_vs_reset_ind mme_sent;
                struct hpav_mtk_vs_reset_rsp *response;
                // Broadcast by default
                unsigned char dest_mac[ETH_MAC_ADDRESS_SIZE] = {
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
                if (argc > 0) {
                    if (!hpav_stomac(argv[0], dest_mac)) {
                        printf("An error occured. Input mac value is in valid format...\n");
                        return -1;
                    }
                }

                printf("Interface successfully opened\n");
                // Sending MME on the channel
                printf("Sending Mstar VS_RESET.IND on the channel\n");
                result = hpav_mtk_vs_reset_ind_sndrcv(current_chan, dest_mac,
                                                      &mme_sent, &response,
                                                      1000, 0, &error_stack);

                if (result != HPAV_OK) {
                    printf("An error occured. Dumping error stack...\n");
                    hpav_dump_error_stack(error_stack);
                    hpav_free_error_stack(&error_stack);
                }
                // Close channel
                hpav_close_channel(current_chan);
                printf("Interface closed\n");
            } else {
                printf("Error while opening the interface\n");
                hpav_dump_error_stack(error_stack);
                hpav_free_error_stack(&error_stack);
            }
        } else {
            unsigned int num_interfaces =
                hpav_get_number_of_interfaces(interfaces);
            printf("Interface number %d not found (0-%d available)\n",
                   interface_num_to_open, (num_interfaces - 1));
        }
        // Free list of interfaces
        hpav_free_interfaces(interfaces);
    } else {
        printf("No interface available\n");
    }
    return 0;
}

void dump_mtk_vs_get_nvram_cnf(struct hpav_mtk_vs_get_nvram_cnf *response) {
    int sta_num = 1, i, j;
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
        printf("Result                                                : %s\n",
               (response->result == 0)
                   ? "SUCCESS"
                   : ((response->result == 1) ? "FAILURE" : "BAD_INDEX"));
        printf("Index                                                 : %d\n",
               response->index);
        printf("Nvram size                                            : %d\n",
               (response->nvram_size));
        printf("NVRAM contents                                        : \n");

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
        sta_num++;
        response = response->next;
    }
}
int test_mme_mtk_vs_get_nvram_req(int interface_num_to_open, int argc,
                                  char *argv[]) {
    struct hpav_if *interfaces = NULL;
    struct hpav_error *error_stack = NULL;
    // Parameters
    if (argc < 2) {
        printf("Mandatory parameters : sta_mac_address block_index\n");
        printf("sta_mac_address : MAC address of the destination STA\n");
        printf("block_index : 1024-byte nvram block to read\n");
        return -1;
    }

    // Get list of interfaces from libhpav
    if (hpav_get_interfaces(&interfaces, &error_stack) != HPAV_OK) {
        printf("An error occured. Dumping error stack...\n");
        hpav_dump_error_stack(error_stack);
        hpav_free_error_stack(&error_stack);
        return -1;
    }

    if (interfaces != NULL) {
        struct hpav_if *interface_to_open = NULL;
        // Get interface
        interface_to_open =
            hpav_get_interface_by_index(interfaces, interface_num_to_open);

        // Check if an interface with this number was found
        if (interface_to_open != NULL) {
            struct hpav_chan *current_chan = NULL;
            // Open the interface
            printf("Opening interface %d : %s (%s)\n", interface_num_to_open,
                   interface_to_open->name,
                   (interface_to_open->description != NULL
                        ? interface_to_open->description
                        : "no description"));
            current_chan = hpav_open_channel(interface_to_open, &error_stack);
            if (current_chan != NULL) {
                int result = -1;
                struct hpav_mtk_vs_get_nvram_req mme_sent;
                struct hpav_mtk_vs_get_nvram_cnf *response;
                // Broadcast by default
                unsigned char dest_mac[ETH_MAC_ADDRESS_SIZE] = {
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
                if (argc > 0) {
                    if (!hpav_stomac(argv[0], dest_mac)) {
                        printf("An error occured. Input mac value is in valid format...\n");
                        return -1;
                    }
                }

                printf("Interface successfully opened\n");
                // REQ parameters (block_index)
                mme_sent.index = (unsigned char)atoi(argv[1]);

                // Sending MME on the channel
                printf("Sending Mstar VS_GET_NVRAM.REQ on the channel for "
                       "block index %d\n",
                       mme_sent.index);
                result = hpav_mtk_vs_get_nvram_sndrcv(current_chan, dest_mac,
                                                      &mme_sent, &response,
                                                      1000, 0, &error_stack);
                if (result != HPAV_OK) {
                    printf("An error occured. Dumping error stack...\n");
                    hpav_dump_error_stack(error_stack);
                    hpav_free_error_stack(&error_stack);
                } else {
                    // Dump response
                    dump_mtk_vs_get_nvram_cnf(response);
                }
                // Free response
                hpav_free_mtk_vs_get_nvram_cnf(response);
                // Close channel
                hpav_close_channel(current_chan);
                printf("Interface closed\n");
            } else {
                printf("Error while opening the interface\n");
                hpav_dump_error_stack(error_stack);
                hpav_free_error_stack(&error_stack);
            }
        } else {
            unsigned int num_interfaces =
                hpav_get_number_of_interfaces(interfaces);
            printf("Interface number %d not found (0-%d available)\n",
                   interface_num_to_open, (num_interfaces - 1));
        }
        // Free list of interfaces
        hpav_free_interfaces(interfaces);
    } else {
        printf("No interface available\n");
    }
    return 0;
}

void dump_mtk_vs_get_tonemask_cnf(
    struct hpav_mtk_vs_get_tonemask_cnf *response) {
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
        if (!response->result) {
            printf("Tonemask                                              :\n");
            hpav_dump_bitfield(response->tonemask, MTK_TONEMASK_SIZE);
            printf("\n");
        }
        sta_num++;
        response = response->next;
    }
}
int test_mme_mtk_vs_get_tonemask_req(int interface_num_to_open, int argc,
                                     char *argv[]) {
    struct hpav_if *interfaces = NULL;
    struct hpav_error *error_stack = NULL;
    // Get list of interfaces from libhpav
    if (hpav_get_interfaces(&interfaces, &error_stack) != HPAV_OK) {
        printf("An error occured. Dumping error stack...\n");
        hpav_dump_error_stack(error_stack);
        hpav_free_error_stack(&error_stack);
        return -1;
    }
    // Parameters
    if (argc < 1) {
        printf("Mandatory parameter : sta_mac_address \n");
        printf("sta_mac_address : MAC address of the destination STA\n");
        return -1;
    }
    if (interfaces != NULL) {
        struct hpav_if *interface_to_open = NULL;
        // Get interface
        interface_to_open =
            hpav_get_interface_by_index(interfaces, interface_num_to_open);

        // Check if an interface with this number was found
        if (interface_to_open != NULL) {
            struct hpav_chan *current_chan = NULL;
            // Open the interface
            printf("Opening interface %d : %s (%s)\n", interface_num_to_open,
                   interface_to_open->name,
                   (interface_to_open->description != NULL
                        ? interface_to_open->description
                        : "no description"));
            current_chan = hpav_open_channel(interface_to_open, &error_stack);
            if (current_chan != NULL) {
                int result = -1;
                struct hpav_mtk_vs_get_tonemask_req mme_sent;
                struct hpav_mtk_vs_get_tonemask_cnf *response;
                // Broadcast by default
                unsigned char dest_mac[ETH_MAC_ADDRESS_SIZE] = {
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
                if (argc > 0) {
                    if (!hpav_stomac(argv[0], dest_mac)) {
                        printf("An error occured. Input mac value is in valid format...\n");
                        return -1;
                    }
                }
                // Parameters
                if (!hpav_stomac(argv[1], mme_sent.peer_mac_addr)) {
                    printf("An error occured. Input mac value is in valid format...\n");
                    return -1;
                }
                printf("Interface successfully opened\n");
                // Sending MME on the channel
                printf("Sending Mstar VS_GET_TONEMASK.REQ on the channel\n");
                result = hpav_mtk_vs_get_tonemask_sndrcv(current_chan, dest_mac,
                                                         &mme_sent, &response,
                                                         1000, 0, &error_stack);
                if (result != HPAV_OK) {
                    printf("An error occured. Dumping error stack...\n");
                    hpav_dump_error_stack(error_stack);
                    hpav_free_error_stack(&error_stack);
                } else {
                    // Dump response
                    dump_mtk_vs_get_tonemask_cnf(response);
                }
                // Free response
                hpav_free_mtk_vs_get_tonemask_cnf(response);
                // Close channel
                hpav_close_channel(current_chan);
                printf("Interface closed\n");
            } else {
                printf("Error while opening the interface\n");
                hpav_dump_error_stack(error_stack);
                hpav_free_error_stack(&error_stack);
            }
        } else {
            unsigned int num_interfaces =
                hpav_get_number_of_interfaces(interfaces);
            printf("Interface number %d not found (0-%d available)\n",
                   interface_num_to_open, (num_interfaces - 1));
        }
        // Free list of interfaces
        hpav_free_interfaces(interfaces);
    } else {
        printf("No interface available\n");
    }
    return 0;
}

void dump_mtk_vs_get_eth_phy_cnf(struct hpav_mtk_vs_get_eth_phy_cnf *response) {
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
        printf("Link Status                                           : %d\n",
               response->link);
        printf("Speed                                                 : %d\n",
               response->speed);
        printf("duplex                                                : %d\n",
               response->duplex);
        printf("PHY address                                           : %d\n",
               response->phy_addr);
        printf("\n");
        sta_num++;
        response = response->next;
    }
}
int test_mme_mtk_vs_get_eth_phy_req(int interface_num_to_open, int argc,
                                    char *argv[]) {
    struct hpav_if *interfaces = NULL;
    struct hpav_error *error_stack = NULL;
    // Get list of interfaces from libhpav
    if (hpav_get_interfaces(&interfaces, &error_stack) != HPAV_OK) {
        printf("An error occured. Dumping error stack...\n");
        hpav_dump_error_stack(error_stack);
        hpav_free_error_stack(&error_stack);
        return -1;
    }

    if (interfaces != NULL) {
        struct hpav_if *interface_to_open = NULL;
        // Get interface
        interface_to_open =
            hpav_get_interface_by_index(interfaces, interface_num_to_open);

        // Check if an interface with this number was found
        if (interface_to_open != NULL) {
            struct hpav_chan *current_chan = NULL;
            // Open the interface
            printf("Opening interface %d : %s (%s)\n", interface_num_to_open,
                   interface_to_open->name,
                   (interface_to_open->description != NULL
                        ? interface_to_open->description
                        : "no description"));
            current_chan = hpav_open_channel(interface_to_open, &error_stack);
            if (current_chan != NULL) {
                int result = -1;
                struct hpav_mtk_vs_get_eth_phy_req mme_sent;
                struct hpav_mtk_vs_get_eth_phy_cnf *response;
                // Broadcast by default
                unsigned char dest_mac[ETH_MAC_ADDRESS_SIZE] = {
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
                if (argc > 0) {
                    if (!hpav_stomac(argv[0], dest_mac)) {
                        printf("An error occured. Input mac value is in valid format...\n");
                        return -1;
                    }
                }

                printf("Interface successfully opened\n");
                // Sending MME on the channel
                printf("Sending Mstar VS_GET_ETH_PHY.REQ on the channel\n");
                result = hpav_mtk_vs_get_eth_phy_sndrcv(current_chan, dest_mac,
                                                        &mme_sent, &response,
                                                        1000, 0, &error_stack);
                if (result != HPAV_OK) {
                    printf("An error occured. Dumping error stack...\n");
                    hpav_dump_error_stack(error_stack);
                    hpav_free_error_stack(&error_stack);
                } else {
                    // Dump response
                    dump_mtk_vs_get_eth_phy_cnf(response);
                }
                // Free response
                hpav_free_mtk_vs_get_eth_phy_cnf(response);
                // Close channel
                hpav_close_channel(current_chan);
                printf("Interface closed\n");
            } else {
                printf("Error while opening the interface\n");
                hpav_dump_error_stack(error_stack);
                hpav_free_error_stack(&error_stack);
            }
        } else {
            unsigned int num_interfaces =
                hpav_get_number_of_interfaces(interfaces);
            printf("Interface number %d not found (0-%d available)\n",
                   interface_num_to_open, (num_interfaces - 1));
        }
        // Free list of interfaces
        hpav_free_interfaces(interfaces);
    } else {
        printf("No interface available\n");
    }
    return 0;
}

void dump_mtk_vs_eth_stats_cnf(struct hpav_mtk_vs_eth_stats_cnf *response) {
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
        printf("Total packets received                                : %u\n",
               response->rx_packets);
        printf("Total packets received with no error                  : %u\n",
               response->rx_good_packets);
        printf("Good unitcast packets received                        : %u\n",
               response->rx_good_unitcast_packets);
        printf("Good multicast packets received                       : %u\n",
               response->rx_good_multicast_packets);
        printf("Good broadcast packets received                       : %u\n",
               response->rx_good_broadcast_packets);
        printf("Total packets received with error                     : %u\n",
               response->rx_error_packets);
        printf("Packets dropped due to rx fifo overflow               : %u\n",
               response->rx_fifo_overflow);
        printf("Total packets transmitted                             : %u\n",
               response->tx_packets);
        printf("Total packets transmitted with no error               : %u\n",
               response->tx_good_packets);
        printf("Packet aborted dueo carrier sense error               : %u\n",
               response->tx_carrier_error);
        printf("Good unitcast packets transmitted                     : %u\n",
               response->tx_good_unitcast_packets);
        printf("Good multicast packets transmitted                    : %u\n",
               response->tx_good_multicast_packets);
        printf("Good broadcast packets transmitted                    : %u\n",
               response->tx_good_broadcast_packets);
        printf("Total packets transmitted with error                  : %u\n",
               response->tx_error_packets);
        printf("Packets aborted due to tx fifo underflow              : %u\n",
               response->tx_fifo_underflow);
        printf("Packets transmitted error due to a collision          : %u\n",
               response->tx_collision);
        printf("Packets aborted due to carrier sense error            : %u\n",
               response->tx_carrier_error);
        printf("\n");
        sta_num++;
        response = response->next;
    }
}
int test_mme_mtk_vs_eth_stats_req(int interface_num_to_open, int argc,
                                  char *argv[]) {
    struct hpav_if *interfaces = NULL;
    struct hpav_error *error_stack = NULL;
    int command;
    // Parameters
    if (argc < 2) {
        printf("Mandatory parameters : sta_mac_address command\n");
        printf("sta_mac_address : MAC address of the destination STA\n");
        printf("command : 0 to get stats, 1 to reset\n");
        return -1;
    }
    command = atoi(argv[1]);

    // Get list of interfaces from libhpav
    if (hpav_get_interfaces(&interfaces, &error_stack) != HPAV_OK) {
        printf("An error occured. Dumping error stack...\n");
        hpav_dump_error_stack(error_stack);
        hpav_free_error_stack(&error_stack);
        return -1;
    }

    if (interfaces != NULL) {
        struct hpav_if *interface_to_open = NULL;
        // Get interface
        interface_to_open =
            hpav_get_interface_by_index(interfaces, interface_num_to_open);

        // Check if an interface with this number was found
        if (interface_to_open != NULL) {
            struct hpav_chan *current_chan = NULL;
            // Open the interface
            printf("Opening interface %d : %s (%s)\n", interface_num_to_open,
                   interface_to_open->name,
                   (interface_to_open->description != NULL
                        ? interface_to_open->description
                        : "no description"));
            current_chan = hpav_open_channel(interface_to_open, &error_stack);
            if (current_chan != NULL) {
                int result = -1;
                struct hpav_mtk_vs_eth_stats_req mme_sent;
                struct hpav_mtk_vs_eth_stats_cnf *response;
                // Broadcast by default
                unsigned char dest_mac[ETH_MAC_ADDRESS_SIZE] = {
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
                if (argc > 0) {
                    if (!hpav_stomac(argv[0], dest_mac)) {
                        printf("An error occured. Input mac value is in valid format...\n");
                        return -1;
                    }
                }

                printf("Interface successfully opened\n");
                // Parameters
                mme_sent.command = command;
                // Sending MME on the channel
                printf("Sending Mstar VS_ETH_STATS.REQ on the channel\n");
                result = hpav_mtk_vs_eth_stats_sndrcv(current_chan, dest_mac,
                                                      &mme_sent, &response,
                                                      1000, 0, &error_stack);
                if (result != HPAV_OK) {
                    printf("An error occured. Dumping error stack...\n");
                    hpav_dump_error_stack(error_stack);
                    hpav_free_error_stack(&error_stack);
                } else {
                    // Dump response
                    dump_mtk_vs_eth_stats_cnf(response);
                }
                // Free response
                hpav_free_mtk_vs_eth_stats_cnf(response);
                // Close channel
                hpav_close_channel(current_chan);
                printf("Interface closed\n");
            } else {
                printf("Error while opening the interface\n");
                hpav_dump_error_stack(error_stack);
                hpav_free_error_stack(&error_stack);
            }
        } else {
            unsigned int num_interfaces =
                hpav_get_number_of_interfaces(interfaces);
            printf("Interface number %d not found (0-%d available)\n",
                   interface_num_to_open, (num_interfaces - 1));
        }
        // Free list of interfaces
        hpav_free_interfaces(interfaces);
    } else {
        printf("No interface available\n");
    }
    return 0;
}

void dump_mtk_vs_get_status_cnf(struct hpav_mtk_vs_get_status_cnf *response) {
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
        printf("Status                                                : %d\n",
               response->status);
        printf("Is CCO                                                : %d\n",
               response->cco);
        printf("Is preferred CCO ?                                    : %d\n",
               response->preferred_cco);
        printf("Is backup CCO                                         : %d\n",
               response->backup_cco);
        printf("Is proxy CCO                                          : %d\n",
               response->proxy_cco);
        printf("Is processing Simple Connect                          : %d\n",
               response->simple_connect);
        printf("Link Connect Status                                   : %d\n",
               response->link_connect_status);
        printf("Ready for PLC operation                               : %d\n",
               response->ready_operation);
        printf("Frequency error (mppm)                                : %lld\n",
               response->freq_error);
        printf("Frequency offset (mppm)                               : %lld\n",
               response->freq_offset);
        printf("Uptime (sec)                                          : %llu\n",
               response->uptime);
        printf("Authenticated time (sec)                              : %llu\n",
               response->authenticated_time);
        printf("Authenticated counts                                  : %u\n",
               response->authenticated_count);
        printf("\n");
        sta_num++;
        response = response->next;
    }
}
int test_mme_mtk_vs_get_status_req(int interface_num_to_open, int argc,
                                   char *argv[]) {
    struct hpav_if *interfaces = NULL;
    struct hpav_error *error_stack = NULL;

    // Get list of interfaces from libhpav
    if (hpav_get_interfaces(&interfaces, &error_stack) != HPAV_OK) {
        printf("An error occured. Dumping error stack...\n");
        hpav_dump_error_stack(error_stack);
        hpav_free_error_stack(&error_stack);
        return -1;
    }

    if (interfaces != NULL) {
        struct hpav_if *interface_to_open = NULL;
        // Get interface
        interface_to_open =
            hpav_get_interface_by_index(interfaces, interface_num_to_open);

        // Check if an interface with this number was found
        if (interface_to_open != NULL) {
            struct hpav_chan *current_chan = NULL;
            // Open the interface
            printf("Opening interface %d : %s (%s)\n", interface_num_to_open,
                   interface_to_open->name,
                   (interface_to_open->description != NULL
                        ? interface_to_open->description
                        : "no description"));
            current_chan = hpav_open_channel(interface_to_open, &error_stack);
            if (current_chan != NULL) {
                int result = -1;
                struct hpav_mtk_vs_get_status_req mme_sent;
                struct hpav_mtk_vs_get_status_cnf *response;
                // Broadcast by default
                unsigned char dest_mac[ETH_MAC_ADDRESS_SIZE] = {
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
                if (argc > 0) {
                    if (!hpav_stomac(argv[0], dest_mac)) {
                        printf("An error occured. Input mac value is in valid format...\n");
                        return -1;
                    }
                }

                printf("Interface successfully opened\n");
                // Sending MME on the channel
                printf("Sending Mstar VS_GET_STATUS.REQ on the channel\n");
                result = hpav_mtk_vs_get_status_sndrcv(current_chan, dest_mac,
                                                       &mme_sent, &response,
                                                       1000, 0, &error_stack);
                if (result != HPAV_OK) {
                    printf("An error occured. Dumping error stack...\n");
                    hpav_dump_error_stack(error_stack);
                    hpav_free_error_stack(&error_stack);
                } else {
                    // Dump response
                    dump_mtk_vs_get_status_cnf(response);
                }
                // Free response
                hpav_free_mtk_vs_get_status_cnf(response);
                // Close channel
                hpav_close_channel(current_chan);
                printf("Interface closed\n");
            } else {
                printf("Error while opening the interface\n");
                hpav_dump_error_stack(error_stack);
                hpav_free_error_stack(&error_stack);
            }
        } else {
            unsigned int num_interfaces =
                hpav_get_number_of_interfaces(interfaces);
            printf("Interface number %d not found (0-%d available)\n",
                   interface_num_to_open, (num_interfaces - 1));
        }
        // Free list of interfaces
        hpav_free_interfaces(interfaces);
    } else {
        printf("No interface available\n");
    }
    return 0;
}

void dump_mtk_vs_get_tonemap_cnf(struct hpav_mtk_vs_get_tonemap_cnf *response,
                                 unsigned int rle) {
#define MAX_FEC_INFO 4
    int sta_num = 1;
    char fec_info[MAX_FEC_INFO][8] = {"1/2", "16/21", "16/18", "undef"};

    printf("--- Response from stations ---\n");
    if (response == NULL) {
        printf("No STA answered\n\n");
        return;
    }

    while (response != NULL) {
        char buffer[64];
        int tonemap_index;
        int int_index;
        printf("Station %d :\n", sta_num);
        printf("MAC address                                           : %s\n",
               hpav_mactos(response->sta_mac_addr, buffer));
        printf("Result                                                : %d\n",
               response->result);
        printf("Beacon delta in 25MHz tick (40ns)                     : %d\n",
               response->beacon_delta);
        printf("Current tonemap interval list identifier              : %d\n",
               response->int_id);
        printf("Tonemap index of default tonemap                      : %d\n",
               response->tmi_default);
        printf("Number of entries in valid tonemap index list         : %d\n",
               response->tmi_length);
        // TMI values
        for (tonemap_index = 0; tonemap_index < response->tmi_length;
             ++tonemap_index) {
            printf("  Valid tonemap index %d : %d\n", tonemap_index,
                   response->tmi_data[tonemap_index]);
        }
        // INT values
        printf("Number of entries in interval list                    : %d\n",
               response->int_length);
        for (int_index = 0; int_index < response->int_length; ++int_index) {
            printf("  End time (in 10.24us) of interval %d : %d\n", int_index,
                   response->int_data[int_index].int_et);
            printf("  TMI of interval %d                   : %d\n", int_index,
                   response->int_data[int_index].int_tmi);
            printf("  Average RX GAIN of interval %d       : %d\n", int_index,
                   response->int_data[int_index].int_rx_gain);
            printf("  FEC of interval %d                   : %d (%s)\n",
                   int_index, response->int_data[int_index].int_fec,
                   (response->int_data[int_index].int_fec < MAX_FEC_INFO)
                       ? fec_info[response->int_data[int_index].int_fec]
                       : fec_info[MAX_FEC_INFO - 1]);
            printf("  GI of interval %d                    : %d\n", int_index,
                   response->int_data[int_index].int_gi);
            printf("  PHY RATE of interval %d              : %d\n", int_index,
                   response->int_data[int_index].int_phy_rate);
        }

        printf("Tonemap index used during interval #0                 : %d\n",
               response->tmi);
        printf("Rx gain of requested tonemap                          : %d\n",
               response->tm_rx_gain);
        printf(
            "FEC code rate of requested tonemap                    : %d (%s)\n",
            response->tm_fec,
            (response->tm_fec < MAX_FEC_INFO) ? fec_info[response->tm_fec]
                                              : fec_info[MAX_FEC_INFO - 1]);
        printf("Guard interval of requested tonemap                   : %d\n",
               response->tm_gi);
        printf("PHY RATE of requested tonemap                         : %d\n",
               response->tm_phy_rate);
        if (response->tmi < 255) {
            if (response->carrier_group == 0xFF) {
                printf("Enable RLE                                            "
                       ": 1\n");
                printf("RLE length of requested tonemap                       "
                       ": %d\n",
                       response->tonemap_length);
            } else {
                printf("Enable RLE                                            "
                       ": 0\n");
                printf("Carriers number of requested tonemap                  "
                       ": %d\n",
                       (response->tonemap_length + 2) / 4);
            }
            printf("List of modulations                                   :\n");
            hpav_dump_tonemap(response->modulation_list,
                              response->tonemap_length,
                              response->carrier_group);
            printf("\n");
        }
        sta_num++;
        response = response->next;
    }
}

int test_mme_mtk_vs_get_tonemap_req(int interface_num_to_open, int argc,
                                    char *argv[]) {
    struct hpav_if *interfaces = NULL;
    struct hpav_error *error_stack = NULL;
    unsigned char remote_sta_mac_addr[ETH_MAC_ADDRESS_SIZE];
    unsigned int tmi;
    unsigned int int_id;
    unsigned int direction;
    unsigned int carrier_group;
    // Parameters
    if (argc < 6) {
        printf("Mandatory parameters   : sta_mac_address "
               "remote_sta_mac_address tmi int_id direction carrier_group\n");
        printf("sta_mac_address        : MAC address of the destination STA\n");
        printf("remote_sta_mac_address : MAC address of remote peer station "
               "where is applied the requested tonemap\n");
        printf("tmi                    : tonemap index of wanted tonemap\n");
        printf("int_id                 : current tonemap interval list "
               "identifier\n");
        printf("direction              : 0 -> TX, 1 -> RX\n");
        printf("carrier_group          : 0/1: carrier group, 255:enable RLE\n");
        return -1;
    }
    if (!hpav_stomac(argv[1], remote_sta_mac_addr)) {
        printf("An error occured. Input mac value is in valid format...\n");
        return -1;
    }
    tmi = atoi(argv[2]);
    int_id = atoi(argv[3]);
    direction = atoi(argv[4]);
    carrier_group = atoi(argv[5]);

    // Get list of interfaces from libhpav
    if (hpav_get_interfaces(&interfaces, &error_stack) != HPAV_OK) {
        printf("An error occured. Dumping error stack...\n");
        hpav_dump_error_stack(error_stack);
        hpav_free_error_stack(&error_stack);
        return -1;
    }

    if (interfaces != NULL) {
        struct hpav_if *interface_to_open = NULL;
        // Get interface
        interface_to_open =
            hpav_get_interface_by_index(interfaces, interface_num_to_open);

        // Check if an interface with this number was found
        if (interface_to_open != NULL) {
            struct hpav_chan *current_chan = NULL;
            // Open the interface
            printf("Opening interface %d : %s (%s)\n", interface_num_to_open,
                   interface_to_open->name,
                   (interface_to_open->description != NULL
                        ? interface_to_open->description
                        : "no description"));
            current_chan = hpav_open_channel(interface_to_open, &error_stack);
            if (current_chan != NULL) {
                int result = -1;
                struct hpav_mtk_vs_get_tonemap_req mme_sent;
                struct hpav_mtk_vs_get_tonemap_cnf *response;
                // Broadcast by default
                unsigned char dest_mac[ETH_MAC_ADDRESS_SIZE] = {
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
                if (argc > 0) {
                    if (!hpav_stomac(argv[0], dest_mac)) {
                        printf("An error occured. Input mac value is in valid format...\n");
                        return -1;
                    }
                }

                printf("Interface successfully opened\n");
                // Parameters
                memcpy(mme_sent.remote_sta_addr, remote_sta_mac_addr,
                       ETH_MAC_ADDRESS_SIZE);
                mme_sent.tmi = tmi;
                mme_sent.int_id = int_id;
                mme_sent.direction = direction;
                mme_sent.carrier_group = carrier_group;
                // Sending MME on the channel
                printf("Sending Mstar VS_GET_TONEMAP.REQ on the channel\n");
                result = hpav_mtk_vs_get_tonemap_sndrcv(current_chan, dest_mac,
                                                        &mme_sent, &response,
                                                        2000, 1, &error_stack);
                if (result != HPAV_OK) {
                    printf("An error occured. Dumping error stack...\n");
                    hpav_dump_error_stack(error_stack);
                    hpav_free_error_stack(&error_stack);
                } else {
                    // Dump response
                    dump_mtk_vs_get_tonemap_cnf(
                        response, (carrier_group == 0xff) ? 1 : 0);
                }
                // Free response
                hpav_free_mtk_vs_get_tonemap_cnf(response);
                // Close channel
                hpav_close_channel(current_chan);
                printf("Interface closed\n");
            } else {
                printf("Error while opening the interface\n");
                hpav_dump_error_stack(error_stack);
                hpav_free_error_stack(&error_stack);
            }
        } else {
            unsigned int num_interfaces =
                hpav_get_number_of_interfaces(interfaces);
            printf("Interface number %d not found (0-%d available)\n",
                   interface_num_to_open, (num_interfaces - 1));
        }
        // Free list of interfaces
        hpav_free_interfaces(interfaces);
    } else {
        printf("No interface available\n");
    }
    return 0;
}

void dump_mtk_vs_set_capture_state_cnf(
    struct hpav_mtk_vs_set_capture_state_cnf *response) {
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
        printf("\n");
        sta_num++;
        response = response->next;
    }
}
int test_mme_mtk_vs_set_capture_state_req(int interface_num_to_open, int argc,
                                          char *argv[]) {
    struct hpav_if *interfaces = NULL;
    struct hpav_error *error_stack = NULL;
    unsigned char remote_sta_mac_addr[ETH_MAC_ADDRESS_SIZE];
    unsigned char state;
    unsigned char captured;
    unsigned char captured_source;
    // Parameters
    if (argc < 5) {
        printf("Mandatory parameters : sta_mac_address remote_sta_mac_address "
               "state captured captured_source\n");
        printf("sta_mac_address : MAC address of the destination STA\n");
        printf("remote_sta_mac_address : MAC address of remote peer station\n");
        printf("state : choose modem to start/stop capture data\n");
        printf("captured : choose to capture what kinds of data type\n");
        printf(
            "captured_source : choose to capture what kinds of data source\n");
        return -1;
    }
    if (!hpav_stomac(argv[1], remote_sta_mac_addr)) {
        printf("An error occured. Input mac value is in valid format...\n");
        return -1;
    }
    state = atoi(argv[2]);
    captured = atoi(argv[3]);
    captured_source = atoi(argv[4]);

    // Get list of interfaces from libhpav
    if (hpav_get_interfaces(&interfaces, &error_stack) != HPAV_OK) {
        printf("An error occured. Dumping error stack...\n");
        hpav_dump_error_stack(error_stack);
        hpav_free_error_stack(&error_stack);
        return -1;
    }

    if (interfaces != NULL) {
        struct hpav_if *interface_to_open = NULL;
        // Get interface
        interface_to_open =
            hpav_get_interface_by_index(interfaces, interface_num_to_open);

        // Check if an interface with this number was found
        if (interface_to_open != NULL) {
            struct hpav_chan *current_chan = NULL;
            // Open the interface
            printf("Opening interface %d : %s (%s)\n", interface_num_to_open,
                   interface_to_open->name,
                   (interface_to_open->description != NULL
                        ? interface_to_open->description
                        : "no description"));
            current_chan = hpav_open_channel(interface_to_open, &error_stack);
            if (current_chan != NULL) {
                int result = -1;
                struct hpav_mtk_vs_set_capture_state_req mme_sent;
                struct hpav_mtk_vs_set_capture_state_cnf *response;
                // Broadcast by default
                unsigned char dest_mac[ETH_MAC_ADDRESS_SIZE] = {
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
                if (argc > 0) {
                    if (!hpav_stomac(argv[0], dest_mac)) {
                        printf("An error occured. Input mac value is in valid format...\n");
                        return -1;
                    }
                }

                printf("Interface successfully opened\n");
                // Parameters
                memcpy(mme_sent.remote_sta_addr, remote_sta_mac_addr,
                       ETH_MAC_ADDRESS_SIZE);
                mme_sent.state = state;
                mme_sent.captured = captured;
                mme_sent.captured_source = captured_source;
                // Sending MME on the channel
                printf(
                    "Sending Mstar VS_SET_CAPTURE_STATE.REQ on the channel\n");
                result = hpav_mtk_vs_set_capture_state_sndrcv(
                    current_chan, dest_mac, &mme_sent, &response, 1000, 0,
                    &error_stack);
                if (result != HPAV_OK) {
                    printf("An error occured. Dumping error stack...\n");
                    hpav_dump_error_stack(error_stack);
                    hpav_free_error_stack(&error_stack);
                } else {
                    // Dump response
                    dump_mtk_vs_set_capture_state_cnf(response);
                }
                // Free response
                hpav_free_mtk_vs_set_capture_state_cnf(response);
                // Close channel
                hpav_close_channel(current_chan);
                printf("Interface closed\n");
            } else {
                printf("Error while opening the interface\n");
                hpav_dump_error_stack(error_stack);
                hpav_free_error_stack(&error_stack);
            }
        } else {
            unsigned int num_interfaces =
                hpav_get_number_of_interfaces(interfaces);
            printf("Interface number %d not found (0-%d available)\n",
                   interface_num_to_open, (num_interfaces - 1));
        }
        // Free list of interfaces
        hpav_free_interfaces(interfaces);
    } else {
        printf("No interface available\n");
    }
    return 0;
}

void dump_mtk_vs_get_snr_cnf(struct hpav_mtk_vs_get_snr_cnf *response) {
    int sta_num = 1;
    printf("--- Response from stations ---\n");
    if (response == NULL) {
        printf("No STA answered\n\n");
        return;
    }

    while (response != NULL) {
        char buffer[64];
        unsigned int snr_index;
        int int_index;
        printf("Station %d :\n", sta_num);
        printf("MAC address                                           : %s\n",
               hpav_mactos(response->sta_mac_addr, buffer));
        printf("Result                                                : %d\n",
               response->result);
        printf("Current tonemap interval list identifier              : %d\n",
               response->int_id);
        // INT values
        printf("Number of entries in interval list                    : %d\n",
               response->int_length);
        for (int_index = 0; int_index < response->int_length; ++int_index) {
            printf("  End time (in 10.24us) of interval %d : %d\n", int_index,
                   response->int_data[int_index]);
        }
        unsigned short ber_quantize_factor = 1 << 15;
        // u16 convert to percentage
        float convert_ber =
            (float)response->tm_ber / (float)ber_quantize_factor * 100;
        printf(
            "Average Bit Error Rate                                : %f %%\n",
            convert_ber);
        printf("Carrier Group                                         : %d\n",
               response->carrier_group);
        printf("SNR data                                              :\n");
        // SNR data
        for (snr_index = 0; snr_index < MTK_SNR_LIST_MAX_SIZE; ++snr_index) {
            // snr value is unit digit
            if (response->snr_list[snr_index] < 10 &&
                response->snr_list[snr_index] >= 0)
                printf(" %d ", (char)response->snr_list[snr_index]);
            else
                printf("%d ", (char)response->snr_list[snr_index]);
            if ((snr_index % 8) == 7) {
                printf("\n");
            }
        }
        printf("\n");
        sta_num++;
        response = response->next;
    }
}
int test_mme_mtk_vs_get_snr_req(int interface_num_to_open, int argc,
                                char *argv[]) {
    struct hpav_if *interfaces = NULL;
    struct hpav_error *error_stack = NULL;
    unsigned char remote_sta_mac_addr[ETH_MAC_ADDRESS_SIZE];
    unsigned int int_index;
    unsigned int carrier_group;
    // Parameters
    if (argc < 4) {
        printf("Mandatory parameters : sta_mac_address remote_sta_mac_address "
               "int_index carrier_group\n");
        printf("sta_mac_address : MAC address of the destination STA\n");
        printf("remote_sta_mac_address : MAC address of remote peer station "
               "where is applied the requested snr\n");
        printf("int_index : tonemap interval index\n");
        printf("carrier_group : modulo-4 subcarrier group number\n");
        return -1;
    }
    if (!hpav_stomac(argv[1], remote_sta_mac_addr)) {
        printf("An error occured. Input mac value is in valid format...\n");
        return -1;
    }
    int_index = atoi(argv[2]);
    carrier_group = atoi(argv[3]);

    // Get list of interfaces from libhpav
    if (hpav_get_interfaces(&interfaces, &error_stack) != HPAV_OK) {
        printf("An error occured. Dumping error stack...\n");
        hpav_dump_error_stack(error_stack);
        hpav_free_error_stack(&error_stack);
        return -1;
    }

    if (interfaces != NULL) {
        struct hpav_if *interface_to_open = NULL;
        // Get interface
        interface_to_open =
            hpav_get_interface_by_index(interfaces, interface_num_to_open);

        // Check if an interface with this number was found
        if (interface_to_open != NULL) {
            struct hpav_chan *current_chan = NULL;
            // Open the interface
            printf("Opening interface %d : %s (%s)\n", interface_num_to_open,
                   interface_to_open->name,
                   (interface_to_open->description != NULL
                        ? interface_to_open->description
                        : "no description"));
            current_chan = hpav_open_channel(interface_to_open, &error_stack);
            if (current_chan != NULL) {
                int result = -1;
                struct hpav_mtk_vs_get_snr_req mme_sent;
                struct hpav_mtk_vs_get_snr_cnf *response;
                // Broadcast by default
                unsigned char dest_mac[ETH_MAC_ADDRESS_SIZE] = {
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
                if (argc > 0) {
                    if (!hpav_stomac(argv[0], dest_mac)) {
                        printf("An error occured. Input mac value is in valid format...\n");
                        return -1;
                    }
                }

                printf("Interface successfully opened\n");
                // Parameters
                memcpy(mme_sent.remote_sta_addr, remote_sta_mac_addr,
                       ETH_MAC_ADDRESS_SIZE);
                mme_sent.int_index = int_index;
                mme_sent.carrier_group = carrier_group;
                // Sending MME on the channel
                printf("Sending Mstar VS_GET_SNR.REQ on the channel\n");
                result = hpav_mtk_vs_get_snr_sndrcv(current_chan, dest_mac,
                                                    &mme_sent, &response, 1000,
                                                    0, &error_stack);
                if (result != HPAV_OK) {
                    printf("An error occured. Dumping error stack...\n");
                    hpav_dump_error_stack(error_stack);
                    hpav_free_error_stack(&error_stack);
                } else {
                    // Dump response
                    dump_mtk_vs_get_snr_cnf(response);
                }
                // Free response
                hpav_free_mtk_vs_get_snr_cnf(response);
                // Close channel
                hpav_close_channel(current_chan);
                printf("Interface closed\n");
            } else {
                printf("Error while opening the interface\n");
                hpav_dump_error_stack(error_stack);
                hpav_free_error_stack(&error_stack);
            }
        } else {
            unsigned int num_interfaces =
                hpav_get_number_of_interfaces(interfaces);
            printf("Interface number %d not found (0-%d available)\n",
                   interface_num_to_open, (num_interfaces - 1));
        }
        // Free list of interfaces
        hpav_free_interfaces(interfaces);
    } else {
        printf("No interface available\n");
    }
    return 0;
}

void dump_mtk_vs_get_link_stats_cnf(
    struct hpav_mtk_vs_get_link_stats_cnf *response, unsigned int req_type,
    unsigned int tl_flag) {
    struct hpav_mtk_vs_get_link_stats_cnf_tx_stats tx_stats;
    struct hpav_mtk_vs_get_link_stats_cnf_rx_stats rx_stats;
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
        if (response->result == HPAV_MTK_VS_GET_LINK_STATS_CNF_RESULT_SUCCESS)
            printf("Result                                                : "
                   "SUCCESS\n");
        else
            printf("Result                                                : "
                   "FAILURE\n");
        printf("request identifier                                    : %d\n",
               response->req_id);

        if (response->result == HPAV_MTK_VS_GET_LINK_STATS_CNF_RESULT_SUCCESS &&
            req_type != HPAV_MTK_VS_GET_LINK_STATS_REQ_REQTYPE_RESET_STAT) {
            if (tl_flag == HPAV_MTK_VS_LINK_STATS_REQ_TLFLAG_TX) {
                memcpy(&tx_stats, response->stats, sizeof(tx_stats));
                printf("msdu_seg_success          : %u\n",
                       tx_stats.msdu_seg_success);
                printf("mpdu                      : %u\n", tx_stats.mpdu);
                printf("mpdu_burst                : %u\n", tx_stats.mpdu_burst);
                printf("mpdu_acked                : %u\n", tx_stats.mpdu_acked);
                printf("mpdu_coll                 : %u\n", tx_stats.mpdu_coll);
                printf("mpdu_fail                 : %u\n", tx_stats.mpdu_fail);
                printf("pb_sucess                 : %u\n", tx_stats.pb_sucess);
                printf("pb_dropped                : %u\n", tx_stats.pb_dropped);
                printf("pb_crc_fail               : %u\n",
                       tx_stats.pb_crc_fail);
                printf("buf_shortage_drop         : %u\n",
                       tx_stats.buf_shortage_drop);
            } else if (tl_flag == HPAV_MTK_VS_LINK_STATS_REQ_TLFLAG_RX) {
                memcpy(&rx_stats, response->stats, sizeof(rx_stats));
                printf("msdu_success              : %u\n",
                       rx_stats.msdu_success);
                printf("mpdu                      : %u\n", rx_stats.mpdu);
                printf("mpdu_burst                : %u\n", rx_stats.mpdu_burst);
                printf("mpdu_acked                : %u\n", rx_stats.mpdu_acked);
                printf("mpdu_fail                 : %u\n", rx_stats.mpdu_fail);
                printf("mpdu_icv_fail             : %u\n",
                       rx_stats.mpdu_icv_fail);
                printf("pb                        : %u\n", rx_stats.pb);
                printf("pb_sucess                 : %u\n", rx_stats.pb_sucess);
                printf("pb_duplicated_dropped     : %u\n",
                       rx_stats.pb_duplicated_dropped);
                printf("pb_crc_fail               : %u\n",
                       rx_stats.pb_crc_fail);
                printf("sum_of_ber_in_pb_success  : %llu\n",
                       rx_stats.sum_of_ber_in_pb_success);
                printf("ssn_under_min             : %u\n",
                       rx_stats.ssn_under_min);
                printf("ssn_over_max              : %u\n",
                       rx_stats.ssn_over_max);
                printf("pb_segs_missed            : %u\n",
                       rx_stats.pb_segs_missed);
            }
        }
        printf("\n");
        sta_num++;
        response = response->next;
    }
}
int test_mme_mtk_vs_get_link_stats_req(int interface_num_to_open, int argc,
                                       char *argv[]) {
    struct hpav_if *interfaces = NULL;
    struct hpav_error *error_stack = NULL;
    unsigned int req_type;
    unsigned int req_id;
    unsigned int lid;
    unsigned int tl_flag;
    unsigned int mgmt_flag;
    unsigned char des_src_mac_address[ETH_MAC_ADDRESS_SIZE];
    // Parameters
    if (argc < 7) {
        printf("Mandatory parameters : sta_mac_address req_type req_id lid "
               "tl_flag mgmt_flag des_src_mac_address\n");
        printf("sta_mac_address : MAC address of the destination STA\n");
        printf("req_type : request type\n");
        printf("req_id : request identifier\n");
        printf("lid : link identifier\n");
        printf("tl_flag : transmit link flag\n");
        printf("mgmt_flag : management link flag\n");
        printf("des_src_mac_address : destination/source MAC address\n");
        return -1;
    }
    req_type = atoi(argv[1]);
    req_id = atoi(argv[2]);
    lid = atoi(argv[3]);
    tl_flag = atoi(argv[4]);
    mgmt_flag = atoi(argv[5]);
    if (!hpav_stomac(argv[6], des_src_mac_address)) {
        printf("An error occured. Input mac value is in valid format...\n");
        return -1;
    }

    // Get list of interfaces from libhpav
    if (hpav_get_interfaces(&interfaces, &error_stack) != HPAV_OK) {
        printf("An error occured. Dumping error stack...\n");
        hpav_dump_error_stack(error_stack);
        hpav_free_error_stack(&error_stack);
        return -1;
    }

    if (interfaces != NULL) {
        struct hpav_if *interface_to_open = NULL;
        // Get interface
        interface_to_open =
            hpav_get_interface_by_index(interfaces, interface_num_to_open);

        // Check if an interface with this number was found
        if (interface_to_open != NULL) {
            struct hpav_chan *current_chan = NULL;
            // Open the interface
            printf("Opening interface %d : %s (%s)\n", interface_num_to_open,
                   interface_to_open->name,
                   (interface_to_open->description != NULL
                        ? interface_to_open->description
                        : "no description"));
            current_chan = hpav_open_channel(interface_to_open, &error_stack);
            if (current_chan != NULL) {
                int result = -1;
                struct hpav_mtk_vs_get_link_stats_req mme_sent;
                struct hpav_mtk_vs_get_link_stats_cnf *response;
                // Broadcast by default
                unsigned char dest_mac[ETH_MAC_ADDRESS_SIZE] = {
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
                if (argc > 0) {
                    if (!hpav_stomac(argv[0], dest_mac)) {
                        printf("An error occured. Input mac value is in valid format...\n");
                        return -1;
                    }
                }

                printf("Interface successfully opened\n");
                // Parameters
                mme_sent.req_type = req_type;
                mme_sent.req_id = req_id;
                mme_sent.lid = lid;
                mme_sent.tl_flag = tl_flag;
                mme_sent.mgmt_flag = mgmt_flag;
                memcpy(mme_sent.des_src_mac_addr, des_src_mac_address,
                       ETH_MAC_ADDRESS_SIZE);
                // Sending MME on the channel
                printf("Sending Mstar VS_GET_LINK_STATS.REQ on the channel\n");
                result = hpav_mtk_vs_get_link_stats_sndrcv(
                    current_chan, dest_mac, &mme_sent, &response, 1000, 0,
                    &error_stack);
                if (result != HPAV_OK) {
                    printf("An error occured. Dumping error stack...\n");
                    hpav_dump_error_stack(error_stack);
                    hpav_free_error_stack(&error_stack);
                } else {
                    // Dump response
                    dump_mtk_vs_get_link_stats_cnf(response, req_type, tl_flag);
                }
                // Free response
                hpav_free_mtk_vs_get_link_stats_cnf(response);
                // Close channel
                hpav_close_channel(current_chan);
                printf("Interface closed\n");
            } else {
                printf("Error while opening the interface\n");
                hpav_dump_error_stack(error_stack);
                hpav_free_error_stack(&error_stack);
            }
        } else {
            unsigned int num_interfaces =
                hpav_get_number_of_interfaces(interfaces);
            printf("Interface number %d not found (0-%d available)\n",
                   interface_num_to_open, (num_interfaces - 1));
        }
        // Free list of interfaces
        hpav_free_interfaces(interfaces);
    } else {
        printf("No interface available\n");
    }
    return 0;
}

void dump_mtk_vs_get_nw_info_cnf(struct hpav_mtk_vs_get_nw_info_cnf *response) {
    int sta_num = 1;
    int sta_idx;
    char buffer[64];

    printf("--- Response from stations ---\n");
    if (NULL == response) {
        printf("No STA answered\n\n");
        return;
    }

    while (response != NULL) {
        printf("Station %d :\n", sta_num);
        printf("MAC address                                           : %s\n",
               hpav_mactos(response->sta_mac_addr, buffer));
        printf("Network Identifier                                    : %s\n",
               hpav_nidtos(response->nid, buffer));
        printf("Short Network Identifier                              : %d\n",
               response->snid);
        printf("CCO's Terminal Equipment Identifier                   : %d\n",
               response->cco_tei);
        printf("CCo's MAC Address                                     : %s\n",
               hpav_mactos(response->cco_mac_addr, buffer));
        printf("Number of AV STAs in the AVLN                         : %d\n",
               response->num_nws);
        for (sta_idx = 0; sta_idx < response->num_nws; ++sta_idx) {
            printf("\tTerminal Equipment Identifier of the STA                 "
                   ": %d\n",
                   response->nwinfo[sta_idx].tei);
            printf("\tSta's MAC Address                                        "
                   ": %s\n",
                   hpav_mactos(response->nwinfo[sta_idx].sta_mac_addr, buffer));
            printf("\tAverage TX PHY coded/raw Rate (Mbps)                     "
                   ": %d/%d\n",
                   response->nwinfo[sta_idx].phy_tx_coded,
                   response->nwinfo[sta_idx].phy_tx_raw);
            printf("\tAverage RX PHY coded/raw Rate (Mbps)                     "
                   ": %d/%d\n",
                   response->nwinfo[sta_idx].phy_rx_coded,
                   response->nwinfo[sta_idx].phy_rx_raw);
            printf("\tAGC gain                                                 "
                   ": %d\n",
                   response->nwinfo[sta_idx].agc_gain);
        }
        printf("\n");
        sta_num++;
        response = response->next;
    }
}

int test_mme_mtk_vs_get_nw_info_req(int interface_num_to_open, int argc,
                                    char *argv[]) {
    struct hpav_if *interfaces = NULL;
    struct hpav_error *error_stack = NULL;
    struct hpav_chan *current_chan = NULL;
    struct hpav_if *interface_to_open = NULL;
    struct hpav_mtk_vs_get_nw_info_req mme_sent;
    struct hpav_mtk_vs_get_nw_info_cnf *response;
    unsigned char dest_mac[ETH_MAC_ADDRESS_SIZE] = {0xff, 0xff, 0xff,
                                                    0xff, 0xff, 0xff};
    unsigned int num_interfaces = 0;
    int result = -1;

    // Get list of interfaces from libhpav
    if (hpav_get_interfaces(&interfaces, &error_stack) != HPAV_OK) {
        printf("An error occured. Dumping error stack...\n");
        hpav_dump_error_stack(error_stack);
        hpav_free_error_stack(&error_stack);
        return -1;
    }

    if (NULL == interfaces) {
        printf("No interface available\n");
        return -1;
    }

    // Get interface
    interface_to_open =
        hpav_get_interface_by_index(interfaces, interface_num_to_open);
    if (NULL == interface_to_open) {
        num_interfaces = hpav_get_number_of_interfaces(interfaces);
        printf("Interface number %d not found (0-%d available)\n",
               interface_num_to_open, (num_interfaces - 1));
        hpav_free_interfaces(interfaces);
        return -1;
    }

    // Open the interface
    printf("Opening interface %d : %s (%s)\n", interface_num_to_open,
           interface_to_open->name, (interface_to_open->description != NULL
                                         ? interface_to_open->description
                                         : "no description"));
    current_chan = hpav_open_channel(interface_to_open, &error_stack);
    if (NULL == current_chan) {
        printf("Error while opening the interface\n");
        hpav_dump_error_stack(error_stack);
        hpav_free_error_stack(&error_stack);
        hpav_free_interfaces(interfaces);
        return -1;
    }

    // Sending MME on the channel
    printf("Interface successfully opened\n");
    printf("Sending Mstar VS_GET_NW_INFO.REQ on the channel\n");
    if (argc > 0) {
        if (!hpav_stomac(argv[0], dest_mac)) {
            printf("An error occured. Input mac value is in valid format...\n");
            return -1;
        }
    }

    memset(&mme_sent, 0x0, sizeof(struct hpav_mtk_vs_get_nw_info_req));
    result = hpav_mtk_vs_get_nw_info_sndrcv(current_chan, dest_mac, &mme_sent,
                                            &response, 1000, 0, &error_stack);
    if (result != HPAV_OK) {
        printf("An error occured. Dumping error stack...\n");
        hpav_dump_error_stack(error_stack);
        hpav_free_error_stack(&error_stack);
    } else {
        // Dump response
        dump_mtk_vs_get_nw_info_cnf(response);
    }

    // Free response
    hpav_free_mtk_vs_get_nw_info_cnf(response);
    // Close channel
    hpav_close_channel(current_chan);
    printf("Interface closed\n");
    // Free list of interfaces
    hpav_free_interfaces(interfaces);

    return 0;
}

#define ACTIONS_MAX_LENGTH 8
#define ACTIONS_NUM 2 // mac, dpw
#define TRUE 1
#define FALSE 0

struct mtk_vs_file_access_command_t {
    char name[32];
    unsigned char op;
    unsigned char file_type;
    unsigned char parse_next;
    char file_flag;
    char parameter[32];
    char file_name[128];
    char all_flag;
};

void dump_mtk_vs_get_pwm_stats_cnf(
    struct hpav_mtk_vs_get_pwm_stats_cnf *response) {
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
        printf(
            "Result                                                : %d (%s)\n",
            response->mstatus,
            (response->mstatus == 0)
                ? "SUCCESS"
                : ((response->mstatus == 1) ? "DISABLE" : "NO PWM SIGNAL"));
        printf(
            "Frequency                                             : %d (Hz)\n",
            response->pwm_freq);
        printf("Duty Cycle                                            : %d "
               "(1/1000)\n",
               response->pwm_duty_cycle);
        printf(
            "Voltage                                               : %d (mV or ADC LSB)\n",
            response->pwm_volt);
        printf("SARADC                                                : %d (LSB)\n",
            response->pwm_saradc);

        printf("\n");
        sta_num++;
        response = response->next;
    }
}
int test_mme_mtk_vs_get_pwm_stats_req(int interface_num_to_open, int argc,
                                      char *argv[]) {
    struct hpav_if *interfaces = NULL;
    struct hpav_error *error_stack = NULL;
    // Get list of interfaces from libhpav
    if (hpav_get_interfaces(&interfaces, &error_stack) != HPAV_OK) {
        printf("An error occured. Dumping error stack...\n");
        hpav_dump_error_stack(error_stack);
        hpav_free_error_stack(&error_stack);
        return -1;
    }

    if (interfaces != NULL) {
        struct hpav_if *interface_to_open = NULL;
        // Get interface
        interface_to_open =
            hpav_get_interface_by_index(interfaces, interface_num_to_open);

        // Check if an interface with this number was found
        if (interface_to_open != NULL) {
            struct hpav_chan *current_chan = NULL;
            // Open the interface
            printf("Opening interface %d : %s (%s)\n", interface_num_to_open,
                   interface_to_open->name,
                   (interface_to_open->description != NULL
                        ? interface_to_open->description
                        : "no description"));
            current_chan = hpav_open_channel(interface_to_open, &error_stack);
            if (current_chan != NULL) {
                int result = -1;
                struct hpav_mtk_vs_get_pwm_stats_req mme_sent;
                struct hpav_mtk_vs_get_pwm_stats_cnf *response;
                // Broadcast by default
                unsigned char dest_mac[ETH_MAC_ADDRESS_SIZE] = {
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
                if (argc > 0) {
                    if (!hpav_stomac(argv[0], dest_mac)) {
                        printf("An error occured. Input mac value is in valid format...\n");
                        return -1;
                    }
                }

                printf("Interface successfully opened\n");
                // Sending MME on the channel
                printf("Sending Mstar VS_GET_PWM_STATS.REQ on the channel\n");
                result = hpav_mtk_vs_get_pwm_stats_sndrcv(
                    current_chan, dest_mac, &mme_sent, &response, 1000, 0,
                    &error_stack);
                if (result != HPAV_OK) {
                    printf("An error occured. Dumping error stack...\n");
                    hpav_dump_error_stack(error_stack);
                    hpav_free_error_stack(&error_stack);
                } else {
                    // Dump response
                    dump_mtk_vs_get_pwm_stats_cnf(response);
                }
                // Free response
                hpav_free_mtk_vs_get_pwm_stats_cnf(response);
                // Close channel
                hpav_close_channel(current_chan);
                printf("Interface closed\n");
            } else {
                printf("Error while opening the interface\n");
                hpav_dump_error_stack(error_stack);
                hpav_free_error_stack(&error_stack);
            }
        } else {
            unsigned int num_interfaces =
                hpav_get_number_of_interfaces(interfaces);
            printf("Interface number %d not found (0-%d available)\n",
                   interface_num_to_open, (num_interfaces - 1));
        }
        // Free list of interfaces
        hpav_free_interfaces(interfaces);
    } else {
        printf("No interface available\n");
    }
    return 0;
}

void dump_mtk_vs_get_pwm_conf_cnf(
    struct hpav_mtk_vs_get_pwm_conf_cnf *response) {
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
        printf(
            "PWM mode                                              : %d (%s)\n",
            response->pwm_mode,
            (response->pwm_mode == 0) ? "Disable" : "Enable");
        printf(
            "PWM measures                                          : %d (%s)\n",
            response->pwm_measures,
            (response->pwm_measures == 0) ? "Poll" : "Push");
        printf(
            "PWM measurement period                                : %d (ms)\n",
            response->pwm_period);
        printf(
            "Frequency threshold                                   : %d (Hz)\n",
            response->pwm_freq_thr);
        printf("Duty cycle threshold                                  : %d "
               "(1/1000)\n",
               response->pwm_duty_cycle_thr);
        printf(
            "Voltage threshold                                     : %d (mV)\n",
            response->pwm_volt_thr);
        printf("SARADC LSB                                            : %d (mV/1000)\n",
            response->pwm_saradc_lsb);
        printf("Voltage bias                                          : %d (mV)\n",
            response->pwm_voltage_bias);

        printf("\n");
        sta_num++;
        response = response->next;
    }
}

int test_mme_mtk_vs_get_pwm_conf_req(int interface_num_to_open, int argc,
                                     char *argv[]) {
    struct hpav_if *interfaces = NULL;
    struct hpav_error *error_stack = NULL;
    // Get list of interfaces from libhpav
    if (hpav_get_interfaces(&interfaces, &error_stack) != HPAV_OK) {
        printf("An error occured. Dumping error stack...\n");
        hpav_dump_error_stack(error_stack);
        hpav_free_error_stack(&error_stack);
        return -1;
    }

    if (interfaces != NULL) {
        struct hpav_if *interface_to_open = NULL;
        // Get interface
        interface_to_open =
            hpav_get_interface_by_index(interfaces, interface_num_to_open);

        // Check if an interface with this number was found
        if (interface_to_open != NULL) {
            struct hpav_chan *current_chan = NULL;
            // Open the interface
            printf("Opening interface %d : %s (%s)\n", interface_num_to_open,
                   interface_to_open->name,
                   (interface_to_open->description != NULL
                        ? interface_to_open->description
                        : "no description"));
            current_chan = hpav_open_channel(interface_to_open, &error_stack);
            if (current_chan != NULL) {
                int result = -1;
                struct hpav_mtk_vs_get_pwm_conf_req mme_sent;
                struct hpav_mtk_vs_get_pwm_conf_cnf *response;
                // Broadcast by default
                unsigned char dest_mac[ETH_MAC_ADDRESS_SIZE] = {
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
                if (argc > 0) {
                    if (!hpav_stomac(argv[0], dest_mac)) {
                        printf("An error occured. Input mac value is in valid format...\n");
                        return -1;
                    }
                }

                printf("Interface successfully opened\n");
                // Sending MME on the channel
                printf("Sending Mstar VS_GET_PWM_CONF.REQ on the channel\n");
                result = hpav_mtk_vs_get_pwm_conf_sndrcv(current_chan, dest_mac,
                                                         &mme_sent, &response,
                                                         1000, 0, &error_stack);
                if (result != HPAV_OK) {
                    printf("An error occured. Dumping error stack...\n");
                    hpav_dump_error_stack(error_stack);
                    hpav_free_error_stack(&error_stack);
                } else {
                    // Dump response
                    dump_mtk_vs_get_pwm_conf_cnf(response);
                }
                // Free response
                hpav_free_mtk_vs_get_pwm_conf_cnf(response);
                // Close channel
                hpav_close_channel(current_chan);
                printf("Interface closed\n");
            } else {
                printf("Error while opening the interface\n");
                hpav_dump_error_stack(error_stack);
                hpav_free_error_stack(&error_stack);
            }
        } else {
            unsigned int num_interfaces =
                hpav_get_number_of_interfaces(interfaces);
            printf("Interface number %d not found (0-%d available)\n",
                   interface_num_to_open, (num_interfaces - 1));
        }
        // Free list of interfaces
        hpav_free_interfaces(interfaces);
    } else {
        printf("No interface available\n");
    }
    return 0;
}

void dump_mtk_vs_set_pwm_conf_cnf(
    struct hpav_mtk_vs_set_pwm_conf_cnf *response) {
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
        printf(
            "Result                                                : %d (%s)\n",
            response->mstatus,
            (response->mstatus == 0) ? "Success"
          : (response->mstatus == 255) ? "Operation is prohibited"
          : "Failure");

        printf("\n");
        sta_num++;
        response = response->next;
    }
}

#define SET_PWM_CONF_PARAMETERS_NUM 10

int test_mme_mtk_vs_set_pwm_conf_req(int interface_num_to_open, int argc,
                                     char *argv[]) {
    struct hpav_if *interfaces = NULL;
    struct hpav_error *error_stack = NULL;
    int result = 0;
    struct hpav_mtk_vs_set_pwm_conf_req mme_sent;

    if (argc != SET_PWM_CONF_PARAMETERS_NUM) {
        result = MTK_VS_SET_PWM_CONF_REQ_PARAMETER_FAIL;
    }

    if (result == 0) {
        mme_sent.op = atoi(argv[1]);
        mme_sent.pwm_mode = atoi(argv[2]);
        mme_sent.pwm_measures = atoi(argv[3]);
        mme_sent.pwm_period = atoi(argv[4]);
        mme_sent.pwm_freq_thr = atoi(argv[5]);
        mme_sent.pwm_duty_cycle_thr = atoi(argv[6]);
        mme_sent.pwm_volt_thr = atoi(argv[7]);
        mme_sent.pwm_saradc_lsb = atoi(argv[8]);
        mme_sent.pwm_voltage_bias = atoi(argv[9]);
    }

    if (result != 0) {
        printf("mtk_vs_set_pwm_conf.req  num_interface [mac_address]\n"
               "Mandatory parameters: Peer_MAC OP_code PWM_mode PWM_measures "
               "PWM_measurement_period freq_thr dc_thr vol_thr\n"
               "OP_code (Bit map): \n"
               "    0x01 = PWM mode\n"
               "    0x02 = PWM measures\n"
               "    0x04 = PWM measurement period\n"
               "    0x08 = Frequency change threshold\n"
               "    0x10 = Duty cycle change threshold\n"
               "    0x20 = Voltage change threshold \n"
               "    0x40 = Set SARADC LSB and Voltage bias \n"
               "PWM_mode: 0 (Disable), 1 (Enable) \n"
               "PWM_measures: 0 (Poll), 1 (Push)\n"
               "PWM_measurement_period: 100 ~ 1000 (ms)\n"
               "freq_thr: (Hz)\n"
               "dc_thr: (1/1000)\n"
               "vol_thr: (mV)\n"
               "saradc_lsb: (mV/1000)\n"
               "voltage_bias: (mV)\n"
               "Ex: 00:11:22:33:44:55 127 0 0 100 5 30 500 12981 327\n");
        return MTK_VS_SET_PWM_CONF_REQ_PARAMETER_FAIL;
    }

    // Get list of interfaces from libhpav
    if (hpav_get_interfaces(&interfaces, &error_stack) != HPAV_OK) {
        printf("An error occured. Dumping error stack...\n");
        hpav_dump_error_stack(error_stack);
        hpav_free_error_stack(&error_stack);
        return MTK_VS_SET_PWM_CONF_REQ_PARAMETER_FAIL;
    }

    if (interfaces != NULL) {
        struct hpav_if *interface_to_open = NULL;
        // Get interface
        interface_to_open =
            hpav_get_interface_by_index(interfaces, interface_num_to_open);

        // Check if an interface with this number was found
        if (interface_to_open != NULL) {
            struct hpav_chan *current_chan = NULL;
            // Open the interface
            printf("Opening interface %d : %s (%s)\n", interface_num_to_open,
                   interface_to_open->name,
                   (interface_to_open->description != NULL
                        ? interface_to_open->description
                        : "no description"));
            current_chan = hpav_open_channel(interface_to_open, &error_stack);
            if (current_chan != NULL) {
                int sndrcv_result = -1;
                struct hpav_mtk_vs_set_pwm_conf_cnf *response;
                // Broadcast by default
                unsigned char dest_mac[ETH_MAC_ADDRESS_SIZE] = {
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
                if (argc > 0) {
                    if (!hpav_stomac(argv[0], dest_mac)) {
                        printf("An error occured. Input mac value is in valid format...\n");
                        return -1;
                    }
                }

                printf("Interface successfully opened\n");
                // Sending MME on the channel
                printf("Sending Mstar VS_SET_PWM_CONF.REQ on the channel\n");
                sndrcv_result = hpav_mtk_vs_set_pwm_conf_sndrcv(
                    current_chan, dest_mac, &mme_sent, &response, 1000, 0,
                    &error_stack);
                if (sndrcv_result != HPAV_OK) {
                    printf("An error occured. Dumping error stack...\n");
                    hpav_dump_error_stack(error_stack);
                    hpav_free_error_stack(&error_stack);
                } else {
                    // Dump response
                    dump_mtk_vs_set_pwm_conf_cnf(response);
                }
                // Free response
                hpav_free_mtk_vs_set_pwm_conf_cnf(response);
                // Close channel
                hpav_close_channel(current_chan);
                printf("Interface closed\n");
            } else {
                printf("Error while opening the interface\n");
                hpav_dump_error_stack(error_stack);
                hpav_free_error_stack(&error_stack);
            }
        } else {
            unsigned int num_interfaces =
                hpav_get_number_of_interfaces(interfaces);
            printf("Interface number %d not found (0-%d available)\n",
                   interface_num_to_open, (num_interfaces - 1));
        }
        // Free list of interfaces
        hpav_free_interfaces(interfaces);
    } else {
        printf("No interface available\n");
    }

    return result;
}
void dump_mtk_vs_set_tx_cali_cnf(struct hpav_mtk_vs_set_tx_cali_cnf *response) {
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
        printf("Result                                                : %s\n",
               (response->result == 0) ? "SUCCESS"
               : (response->result == 1) ? "FAILURE"
               : (response->result == 255) ? "Operation is prohibited"
               : "BAD_INDEX");
        sta_num++;
        response = response->next;
    }
}

void dump_mtk_vs_spi_stats_cnf(struct hpav_mtk_vs_spi_stats_cnf *response) {
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
        printf(
            "Result                                                : %u (%s)\n",
            response->result, (response->result == 0) ? "SUCCESS" : "FAILURE");
        printf("Rx packets                                            : %u\n",
               response->rx_packets);
        printf("Rx unicast                                            : %u\n",
               response->rx_ucast);
        printf("Rx CMD_RTS                                            : %u\n",
               response->rx_cmd_rts);
        printf("Rx CMD_RTS error                                      : %u\n",
               response->rx_cmd_rts_err);
        printf("Rx CMD_RTS wrong length                               : %u\n",
               response->rx_cmd_rts_wrong_length);
        printf("Rx data error                                         : %u\n",
               response->rx_data_err);
        printf("Rx abort due to queue full                            : %u\n",
               response->rx_abort_queue_full);
        printf("Rx wait re-assembled fragment length                  : %u\n",
               response->rx_fragment_length);
        printf("Tx packets                                            : %u\n",
               response->tx_packets);
        printf("Tx unicast                                            : %u\n",
               response->tx_ucast);
        printf("Tx CMD_RTS                                            : %u\n",
               response->tx_cmd_rts);
        printf("Tx CMD_CTR                                            : %u\n",
               response->tx_cmd_ctr);
        printf("Tx CMD_RTS timeout                                    : %u\n",
               response->tx_cmd_rts_timeout);
        printf("Tx CMD_CTR timeout                                    : %u\n",
               response->tx_cmd_ctr_timeout);
        printf("Tx packet drop due to queue full                      : %u\n",
               response->tx_packet_drop_queue_full);
        printf("Fragment expire happen                                : %u\n",
               response->fragment_expire);

        printf("\n");
        sta_num++;
        response = response->next;
    }
}

int test_mme_mtk_vs_set_tx_cali_req(int interface_num_to_open, int argc,
                                    char *argv[]) {
    struct hpav_if *interfaces = NULL;
    struct hpav_error *error_stack = NULL;

    // Get list of interfaces from libhpav
    if (hpav_get_interfaces(&interfaces, &error_stack) != HPAV_OK) {
        printf("An error occured. Dumping error stack...\n");
        hpav_dump_error_stack(error_stack);
        hpav_free_error_stack(&error_stack);
        return -1;
    }
	// Parameters
	if (argc < 2) {
		printf("Mandatory parameter : sta_mac_address enable\n");
		printf("sta_mac_address : MAC address of the destination STA\n");
		printf("enable : 0x00/Ox01 = Disable/Enable transmission PSD calibration featur\n");
		return -1;
	}

    if (interfaces != NULL) {
        struct hpav_if *interface_to_open = NULL;
        // Get interface
        interface_to_open =
            hpav_get_interface_by_index(interfaces, interface_num_to_open);

        // Check if an interface with this number was found
        if (interface_to_open != NULL) {
            struct hpav_chan *current_chan = NULL;
            // Open the interface
            printf("Opening interface %d : %s (%s)\n", interface_num_to_open,
                   interface_to_open->name,
                   (interface_to_open->description != NULL
                        ? interface_to_open->description
                        : "no description"));
            current_chan = hpav_open_channel(interface_to_open, &error_stack);
            if (current_chan != NULL) {
                int result = -1;
                struct hpav_mtk_vs_set_tx_cali_req mme_sent;
                struct hpav_mtk_vs_set_tx_cali_cnf *response;
                // Broadcast by default
                unsigned char dest_mac[ETH_MAC_ADDRESS_SIZE] = {
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
                if (argc > 0) {
                    if (!hpav_stomac(argv[0], dest_mac)) {
                        printf("An error occured. Input mac value is in valid format...\n");
                        return -1;
                    }
                }

                printf("Interface successfully opened\n");
                mme_sent.enable = atoi(argv[1]);
                // Sending MME on the channel
                printf("Sending Mstar VS_SET_TX_CALI.REQ on the channel\n");
                result = hpav_mtk_vs_set_tx_cali_sndrcv(current_chan, dest_mac,
                                                        &mme_sent, &response,
                                                        1000, 0, &error_stack);
                if (result != HPAV_OK) {
                    printf("An error occured. Dumping error stack...\n");
                    hpav_dump_error_stack(error_stack);
                    hpav_free_error_stack(&error_stack);
                } else {
                    // Dump response
                    dump_mtk_vs_set_tx_cali_cnf(response);
                }
                // Free response
                hpav_free_mtk_vs_set_tx_cali_cnf(response);
                // Close channel
                hpav_close_channel(current_chan);
                printf("Interface closed\n");
            } else {
                printf("Error while opening the interface\n");
                hpav_dump_error_stack(error_stack);
                hpav_free_error_stack(&error_stack);
            }
        } else {
            unsigned int num_interfaces =
                hpav_get_number_of_interfaces(interfaces);
            printf("Interface number %d not found (0-%d available)\n",
                   interface_num_to_open, (num_interfaces - 1));
        }
        // Free list of interfaces
        hpav_free_interfaces(interfaces);
    } else {
        printf("No interface available\n");
    }
    return 0;
}

int test_mme_mtk_vs_spi_stats_req(int interface_num_to_open, int argc,
                                  char *argv[]) {
    struct hpav_if *interfaces = NULL;
    struct hpav_error *error_stack = NULL;
    unsigned int command;
    // Parameters
    if (argc < 2) {
        printf("Mandatory parameters : sta_mac_address command\n");
        printf("sta_mac_address : MAC address of the destination STA\n");
        printf("command : 0 to get stats, 1 to reset stats\n");
        return -1;
    }
    command = atoi(argv[1]);
    // Get list of interfaces from libhpav
    if (hpav_get_interfaces(&interfaces, &error_stack) != HPAV_OK) {
        printf("An error occured. Dumping error stack...\n");
        hpav_dump_error_stack(error_stack);
        hpav_free_error_stack(&error_stack);
        return -1;
    }

    if (interfaces != NULL) {
        struct hpav_if *interface_to_open = NULL;
        // Get interface
        interface_to_open =
            hpav_get_interface_by_index(interfaces, interface_num_to_open);

        // Check if an interface with this number was found
        if (interface_to_open != NULL) {
            struct hpav_chan *current_chan = NULL;
            // Open the interface
            printf("Opening interface %d : %s (%s)\n", interface_num_to_open,
                   interface_to_open->name,
                   (interface_to_open->description != NULL
                        ? interface_to_open->description
                        : "no description"));
            current_chan = hpav_open_channel(interface_to_open, &error_stack);
            if (current_chan != NULL) {
                int result = -1;
                struct hpav_mtk_vs_spi_stats_req mme_sent;
                struct hpav_mtk_vs_spi_stats_cnf *response;
                // Broadcast by default
                unsigned char dest_mac[ETH_MAC_ADDRESS_SIZE] = {
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
                if (argc > 0) {
                    if (!hpav_stomac(argv[0], dest_mac)) {
                        printf("An error occured. Input mac value is in valid format...\n");
                        return -1;
                    }
                }

                printf("Interface successfully opened\n");
                // Parameters
                mme_sent.command = command;
                // Sending MME on the channel
                printf("Sending Mstar VS_SPI_STATS.REQ on the channel\n");
                result = hpav_mtk_vs_spi_stats_sndrcv(current_chan, dest_mac,
                                                      &mme_sent, &response,
                                                      1000, 0, &error_stack);
                if (result != HPAV_OK) {
                    printf("An error occured. Dumping error stack...\n");
                    hpav_dump_error_stack(error_stack);
                    hpav_free_error_stack(&error_stack);
                } else {
                    // Dump response
                    dump_mtk_vs_spi_stats_cnf(response);
                }
                // Free response
                hpav_free_mtk_vs_spi_stats_cnf(response);
                // Close channel
                hpav_close_channel(current_chan);
                printf("Interface closed\n");
            } else {
                printf("Error while opening the interface\n");
                hpav_dump_error_stack(error_stack);
                hpav_free_error_stack(&error_stack);
            }
        } else {
            unsigned int num_interfaces =
                hpav_get_number_of_interfaces(interfaces);
            printf("Interface number %d not found (0-%d available)\n",
                   interface_num_to_open, (num_interfaces - 1));
        }
        // Free list of interfaces
        hpav_free_interfaces(interfaces);
    } else {
        printf("No interface available\n");
    }
    return 0;
}

void dump_mtk_vs_set_tx_cali_ind(struct hpav_mtk_vs_set_tx_cali_ind *response) {
    int sta_num = 1;
    int spectrum_idx = 0;
    int i;
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
        printf("spectrum_idx                                          : %d\n",
               response->spectrum_idx);
        spectrum_idx = response->spectrum_idx;
        if (spectrum_idx != 0 && response->result) {
            printf("Result                                              :\n");
            for (i = 0; i < spectrum_idx; i++) {
                if (i % 16 == 0)
                    printf("\n");
                printf(" %X ", response->result[i]);
            }
            printf("\n");
        }
        sta_num++;
        response = response->next;
    }
}

int test_mme_mtk_vs_set_tx_cali_ind(int interface_num_to_open, int argc,
                                    char *argv[]) {
    struct hpav_if *interfaces = NULL;
    struct hpav_error *error_stack = NULL;
    // Get list of interfaces from libhpav
    if (hpav_get_interfaces(&interfaces, &error_stack) != HPAV_OK) {
        printf("An error occured. Dumping error stack...\n");
        hpav_dump_error_stack(error_stack);
        hpav_free_error_stack(&error_stack);
        return -1;
    }

    if (interfaces != NULL) {
        struct hpav_if *interface_to_open = NULL;
        // Get interface
        interface_to_open =
            hpav_get_interface_by_index(interfaces, interface_num_to_open);

        // Check if an interface with this number was found
        if (interface_to_open != NULL) {
            struct hpav_chan *current_chan = NULL;
            // Open the interface
            printf("Opening interface %d : %s (%s)\n", interface_num_to_open,
                   interface_to_open->name,
                   (interface_to_open->description != NULL
                        ? interface_to_open->description
                        : "no description"));
            current_chan = hpav_open_channel(interface_to_open, &error_stack);
            if (current_chan != NULL) {
                int result = -1;

                struct hpav_mtk_vs_set_tx_cali_ind *response;
                printf("Interface successfully opened\n");

                // Sending MME on the channel
                printf("Recving Mstar VS_SET_TX_CALI.IND on the channel\n");
                result = hpav_mtk_vs_set_tx_cali_ind_rcv(
                    current_chan, &response, 1000, 0, &error_stack);
                if (result != HPAV_OK) {
                    printf("An error occured. Dumping error stack...\n");
                    hpav_dump_error_stack(error_stack);
                    hpav_free_error_stack(&error_stack);
                } else {
                    // Dump response
                    dump_mtk_vs_set_tx_cali_ind(response);
                }
                // Free response
                hpav_free_mtk_vs_set_tx_cali_ind(response);
                // Close channel
                hpav_close_channel(current_chan);
                printf("Interface closed\n");
            } else {
                printf("Error while opening the interface\n");
                hpav_dump_error_stack(error_stack);
                hpav_free_error_stack(&error_stack);
            }
        } else {
            unsigned int num_interfaces =
                hpav_get_number_of_interfaces(interfaces);
            printf("Interface number %d not found (0-%d available)\n",
                   interface_num_to_open, (num_interfaces - 1));
        }
        // Free list of interfaces
        hpav_free_interfaces(interfaces);
    } else {
        printf("No interface available\n");
    }
    return 0;
}

void dump_vc_vs_set_sniffer_conf_cnf(struct hpav_vc_vs_set_sniffer_conf_cnf*
                                    response)
{
    int sta_num = 1;
    char *error_info[] = { "No error",
        "Action of setting failed", "No MPDU sniffer FW",
        "MPDU sniffer FW error" };
    printf("--- Response from stations ---\n");
    if (response == NULL) {
        printf("No STA answered\n\n");
        return;
    }

    while (response != NULL) {
        unsigned char buffer[64];
        printf("Station %d :\n", sta_num);
        printf("MAC address                                           \
            : %s\n", hpav_mactos(response->sta_mac_addr, buffer));
        printf("Result                                                \
            : %d\n", response->mstatus);
        printf("Mode Failure Reason Code                              \
            : %s\n", error_info[response->err_status]);

        printf("\n");
        sta_num++;
        response = response->next;
    }
}
int test_mme_vc_vs_set_sniffer_conf_req(int interface_num_to_open, int argc,
    char *argv[]) {
    struct hpav_if *interfaces = NULL;
    struct hpav_error *error_stack = NULL;
    // Get list of interfaces from libhpav

    int sniffer_mode;
    // Parameters
    if (argc < 2) {
        printf("vc_vs_set_sniffer_conf_req  num_interface [mac_address]\n" \
            "Mandatory parameters: sta_mac_address mode (decimal) " \
            "sta_mac_address : MAC address of the destination STA\n"\
            "mode:  0 (MSDU Sniffer mode), 1 (MPDU Sniffer mode) \n" \
            "Ex: 00:11:22:33:44:55 1\n");
        return -1;
    }
    sniffer_mode = atoi(argv[1]);

    if (hpav_get_interfaces(&interfaces, &error_stack) != HPAV_OK) {
        printf("An error occured. Dumping error stack...\n");
        hpav_dump_error_stack(error_stack);
        hpav_free_error_stack(&error_stack);
        return -1;
    }

    if (interfaces != NULL) {
        struct hpav_if *interface_to_open = NULL;
        // Get interface
        interface_to_open =
            hpav_get_interface_by_index(interfaces, interface_num_to_open);

        // Check if an interface with this number was found
        if (interface_to_open != NULL) {
            struct hpav_chan *current_chan = NULL;
            // Open the interface
            printf("Opening interface %d : %s (%s)\n",
                interface_num_to_open,
                interface_to_open->name,
                (interface_to_open->description != NULL
                    ? interface_to_open->description
                    : "no description"));
            current_chan = hpav_open_channel(interface_to_open,
                &error_stack);
            if (current_chan != NULL) {
                int result = -1;

                struct hpav_vc_vs_set_sniffer_conf_req mme_sent;
                struct hpav_vc_vs_set_sniffer_conf_cnf *response;
                // Broadcast by default
                unsigned char dest_mac[ETH_MAC_ADDRESS_SIZE] =
                    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
                if (argc > 0) {
                    hpav_stomac(argv[0], dest_mac);
                }

                printf("Interface successfully opened\n");
                // Parameters
                mme_sent.sniffer_mode = sniffer_mode;
                // Sending MME on the channel
                printf("Recving VC VS_SET_SNIFFER_CONF.REQ\
                    on the channel\n");
                result = hpav_vc_vs_set_sniffer_conf_sndrcv(
                    current_chan, dest_mac, &mme_sent, &response,
                        1000, 0, &error_stack);
                if (result != HPAV_OK) {
                    printf("An error occured. Dumping error stack...\n");
                    hpav_dump_error_stack(error_stack);
                    hpav_free_error_stack(&error_stack);
                }
                else {
                    // Dump response
                    dump_vc_vs_set_sniffer_conf_cnf(response);
                }
                // Free response
                hpav_free_vc_vs_set_sniffer_conf_cnf(response);
                // Close channel
                hpav_close_channel(current_chan);
                printf("Interface closed\n");
            }
            else {
                printf("Error while opening the interface\n");
                hpav_dump_error_stack(error_stack);
                hpav_free_error_stack(&error_stack);
            }
        }
        else {
            unsigned int num_interfaces =
                hpav_get_number_of_interfaces(interfaces);
            printf("Interface number %d not found (0-%d available)\n",
                interface_num_to_open, (num_interfaces - 1));
        }
        // Free list of interfaces
        hpav_free_interfaces(interfaces);
    }
    else {
        printf("No interface available\n");
    }
    return 0;
}

void dump_vc_vs_get_remote_access_cnf(
    struct hpav_vc_vs_get_remote_access_cnf *response) {
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
        printf(
            "Status                                                : %d (%s)\n",
            response->mstatus,
            (response->mstatus == 0)? "Station's remote access is allowed"
            : (response->mstatus == 1) ? "Station's remote access is prohibited"
            : "RESERVED");

        printf("\n");
        sta_num++;
        response = response->next;
    }
}
int test_mme_vc_vs_get_remote_access_req(int interface_num_to_open, int argc,
                                      char *argv[]) {
    struct hpav_if *interfaces = NULL;
    struct hpav_error *error_stack = NULL;
    // Get list of interfaces from libhpav
    if (hpav_get_interfaces(&interfaces, &error_stack) != HPAV_OK) {
        printf("An error occured. Dumping error stack...\n");
        hpav_dump_error_stack(error_stack);
        hpav_free_error_stack(&error_stack);
        return -1;
    }

    if (interfaces != NULL) {
        struct hpav_if *interface_to_open = NULL;
        // Get interface
        interface_to_open =
            hpav_get_interface_by_index(interfaces, interface_num_to_open);

        // Check if an interface with this number was found
        if (interface_to_open != NULL) {
            struct hpav_chan *current_chan = NULL;
            // Open the interface
            printf("Opening interface %d : %s (%s)\n", interface_num_to_open,
                   interface_to_open->name,
                   (interface_to_open->description != NULL
                        ? interface_to_open->description
                        : "no description"));
            current_chan = hpav_open_channel(interface_to_open, &error_stack);
            if (current_chan != NULL) {
                int result = -1;
                struct hpav_vc_vs_get_remote_access_req mme_sent;
                struct hpav_vc_vs_get_remote_access_cnf *response;
                // Broadcast by default
                unsigned char dest_mac[ETH_MAC_ADDRESS_SIZE] = {
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
                if (argc > 0) {
                    if (!hpav_stomac(argv[0], dest_mac)) {
                        printf("An error occured. Input mac value is in valid format...\n");
                        return -1;
                    }
                }

                printf("Interface successfully opened\n");
                // Sending MME on the channel
                printf("Sending VC_VS_GET_REMOTE_ACCESS.REQ on the channel\n");
                result = hpav_vc_vs_get_remote_access_sndrcv(
                    current_chan, dest_mac, &mme_sent, &response, 1000, 0,
                    &error_stack);
                if (result != HPAV_OK) {
                    printf("An error occured. Dumping error stack...\n");
                    hpav_dump_error_stack(error_stack);
                    hpav_free_error_stack(&error_stack);
                } else {
                    // Dump response
                    dump_vc_vs_get_remote_access_cnf(response);
                }
                // Free response
                hpav_free_vc_vs_get_remote_access_cnf(response);
                // Close channel
                hpav_close_channel(current_chan);
                printf("Interface closed\n");
            } else {
                printf("Error while opening the interface\n");
                hpav_dump_error_stack(error_stack);
                hpav_free_error_stack(&error_stack);
            }
        } else {
            unsigned int num_interfaces =
                hpav_get_number_of_interfaces(interfaces);
            printf("Interface number %d not found (0-%d available)\n",
                   interface_num_to_open, (num_interfaces - 1));
        }
        // Free list of interfaces
        hpav_free_interfaces(interfaces);
    } else {
        printf("No interface available\n");
    }
    return 0;
}


void dump_vc_vs_set_remote_access_cnf(
    struct hpav_vc_vs_set_remote_access_cnf *response) {
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
        printf(
            "Result                                                : %d (%s)\n",
            response->mstatus,
            (response->mstatus == 0) ? "Success"
            : (response->mstatus == 1) ? "Failure"
            : (response->mstatus == 255) ? "Operation is prohibited"
            : "Reserved");
        printf("\n");
        sta_num++;
        response = response->next;
    }
}

int test_mme_vc_vs_set_remote_access_req(int interface_num_to_open, int argc,
                                     char *argv[]) {
    struct hpav_if *interfaces = NULL;
    struct hpav_error *error_stack = NULL;
    int remote_access_mode;
    struct hpav_vc_vs_set_remote_access_req mme_sent;

    if (argc < 2) {
        printf("vc_vs_set_remote_aceess_req num_interface sta_mac_address mode\n" \
               "Mandatory parameters: sta_mac_address mode " \
               "sta_mac_address : MAC address of the destination STA\n"\
               "mode: 0 (Allow remote access), 1 (Prohibit remote access) \n" \
               " Ex: 00:11:22:33:44:55 1\n");
        return -1;
    }
    remote_access_mode = atoi(argv[1]);

    // Get list of interfaces from libhpav
    if (hpav_get_interfaces(&interfaces, &error_stack) != HPAV_OK) {
        printf("An error occured. Dumping error stack...\n");
        hpav_dump_error_stack(error_stack);
        hpav_free_error_stack(&error_stack);
        return -1;
    }

    if (interfaces != NULL) {
        struct hpav_if *interface_to_open = NULL;
        // Get interface
        interface_to_open =
            hpav_get_interface_by_index(interfaces, interface_num_to_open);

        // Check if an interface with this number was found
        if (interface_to_open != NULL) {
            struct hpav_chan *current_chan = NULL;
            // Open the interface
            printf("Opening interface %d : %s (%s)\n", interface_num_to_open,
                   interface_to_open->name,
                   (interface_to_open->description != NULL
                        ? interface_to_open->description
                        : "no description"));
            current_chan = hpav_open_channel(interface_to_open, &error_stack);
            if (current_chan != NULL) {
                int sndrcv_result = -1;
                struct hpav_vc_vs_set_remote_access_req mme_sent;
                struct hpav_vc_vs_set_remote_access_cnf *response;
                // Broadcast by default
                unsigned char dest_mac[ETH_MAC_ADDRESS_SIZE] = {
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
                if (argc > 0) {
                    if (!hpav_stomac(argv[0], dest_mac)) {
                        printf("An error occured. Input mac value is in valid format...\n");
                        return -1;
                    }
                }

                printf("Interface successfully opened\n");
                // Parameters
                mme_sent.remote_access_mode = remote_access_mode;
                // Sending MME on the channel
                printf("Sending VC VS_SET_REMOTE_ACCESS_CONF.REQ on the channel\n");
                sndrcv_result = hpav_vc_vs_set_remote_access_sndrcv(
                    current_chan, dest_mac, &mme_sent, &response, 1000, 0,
                    &error_stack);
                if (sndrcv_result != HPAV_OK) {
                    printf("An error occured. Dumping error stack...\n");
                    hpav_dump_error_stack(error_stack);
                    hpav_free_error_stack(&error_stack);
                } else {
                    // Dump response
                    dump_vc_vs_set_remote_access_cnf(response);
                }
                // Free response
                hpav_free_vc_vs_set_remote_access_cnf(response);
                // Close channel
                hpav_close_channel(current_chan);
                printf("Interface closed\n");
            } else {
                printf("Error while opening the interface\n");
                hpav_dump_error_stack(error_stack);
                hpav_free_error_stack(&error_stack);
            }
        } else {
            unsigned int num_interfaces =
                hpav_get_number_of_interfaces(interfaces);
            printf("Interface number %d not found (0-%d available)\n",
                   interface_num_to_open, (num_interfaces - 1));
        }
        // Free list of interfaces
        hpav_free_interfaces(interfaces);
    } else {
        printf("No interface available\n");
    }

    return 0;
}

void dump_mtk_vs_pwm_generation_cnf(
    struct hpav_mtk_vs_pwm_generation_cnf *response) {
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
        printf("\n");
        sta_num++;
        response = response->next;
    }
}
int test_mme_mtk_vs_pwm_generation_req(int interface_num_to_open, int argc,
                                       char *argv[]) {
    struct hpav_if *interfaces = NULL;
    struct hpav_error *error_stack = NULL;
    unsigned int pmw_mode;
    unsigned int pmw_freq;
    unsigned int pwm_duty_cycle;

    // Parameters
    if (argc < 4) {
        printf("Mandatory parameters : sta_mac_address PWM_mode frequency "
               "duty_cycle\n");
        printf("sta_mac_address : MAC address of the destination STA\n");
        printf("PWM_mode: 0 (Disable), 1 (Enable) \n");
        printf("frequency: (KHz)\n");
        printf("duty_cycle: (%%)\n");
        printf("Ex: 00:11:22:33:44:55 1 10 50\n");
        return -1;
    }
    pmw_mode = atoi(argv[1]);
    pmw_freq = atoi(argv[2]);
    pwm_duty_cycle = atoi(argv[3]);

    // Get list of interfaces from libhpav
    if (hpav_get_interfaces(&interfaces, &error_stack) != HPAV_OK) {
        printf("An error occured. Dumping error stack...\n");
        hpav_dump_error_stack(error_stack);
        hpav_free_error_stack(&error_stack);
        return -1;
    }

    if (interfaces != NULL) {
        struct hpav_if *interface_to_open = NULL;
        // Get interface
        interface_to_open =
            hpav_get_interface_by_index(interfaces, interface_num_to_open);

        // Check if an interface with this number was found
        if (interface_to_open != NULL) {
            struct hpav_chan *current_chan = NULL;
            // Open the interface
            printf("Opening interface %d : %s (%s)\n", interface_num_to_open,
                   interface_to_open->name,
                   (interface_to_open->description != NULL
                        ? interface_to_open->description
                        : "no description"));
            current_chan = hpav_open_channel(interface_to_open, &error_stack);
            if (current_chan != NULL) {
                int result = -1;
                struct hpav_mtk_vs_pwm_generation_req mme_sent;
                struct hpav_mtk_vs_pwm_generation_cnf *response;
                // Broadcast by default
                unsigned char dest_mac[ETH_MAC_ADDRESS_SIZE] = {
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
                if (argc > 0) {
                    if (!hpav_stomac(argv[0], dest_mac)) {
                        printf("An error occured. Input mac value is in valid format...\n");
                        return -1;
                    }
                }

                printf("Interface successfully opened\n");
                // Parameters
                mme_sent.pwm_mode = pmw_mode;
                mme_sent.pwm_freq = pmw_freq;
                mme_sent.pwm_duty_cycle = pwm_duty_cycle;

                // Sending MME on the channel
                printf("Sending Mstar VS_PWM_GENERATION.REQ on the channel\n");
                result = hpav_mtk_vs_pwm_generation_sndrcv(
                    current_chan, dest_mac, &mme_sent, &response, 1000, 0,
                    &error_stack);
                if (result != HPAV_OK) {
                    printf("An error occured. Dumping error stack...\n");
                    hpav_dump_error_stack(error_stack);
                    hpav_free_error_stack(&error_stack);
                } else {
                    // Dump response
                    dump_mtk_vs_pwm_generation_cnf(response);
                }
                // Free response
                hpav_free_mtk_vs_pwm_generation_cnf(response);
                // Close channel
                hpav_close_channel(current_chan);
                printf("Interface closed\n");
            } else {
                printf("Error while opening the interface\n");
                hpav_dump_error_stack(error_stack);
                hpav_free_error_stack(&error_stack);
            }
        } else {
            unsigned int num_interfaces =
                hpav_get_number_of_interfaces(interfaces);
            printf("Interface number %d not found (0-%d available)\n",
                   interface_num_to_open, (num_interfaces - 1));
        }
        // Free list of interfaces
        hpav_free_interfaces(interfaces);
    } else {
        printf("No interface available\n");
    }
    return 0;
}

#define PARSE_NEXT_YES 1
#define PARSE_NEXT_NO 0

#define FILE_FLAG_NONE 0
#define FILE_FLAG_INPUT 1
#define FILE_FLAG_OUTPUT 2

typedef struct mtk_vs_file_access_command_t mtk_vs_file_access_command_t;

typedef unsigned long long mac_t;

mtk_vs_file_access_command_t mtk_vs_file_access_commands[] = {
    {"write", HPAV_MTK_VS_FILE_ACCESS_REQ_OP_WRITE,
     HPAV_MTK_VS_FILE_ACCESS_REQ_FILE_TYPE_GENERAL_FILE, PARSE_NEXT_YES,
     FILE_FLAG_INPUT},
    {"bootloader", HPAV_MTK_VS_FILE_ACCESS_REQ_OP_WRITE,
     HPAV_MTK_VS_FILE_ACCESS_REQ_FILE_TYPE_BOOTLOADER, PARSE_NEXT_NO,
     FILE_FLAG_INPUT},
    {"simage", HPAV_MTK_VS_FILE_ACCESS_REQ_OP_WRITE,
     HPAV_MTK_VS_FILE_ACCESS_REQ_FILE_TYPE_SIMAGE, PARSE_NEXT_YES,
     FILE_FLAG_INPUT},
    {"read", HPAV_MTK_VS_FILE_ACCESS_REQ_OP_READ,
     HPAV_MTK_VS_FILE_ACCESS_REQ_FILE_TYPE_GENERAL_FILE, PARSE_NEXT_YES,
     FILE_FLAG_NONE},
    {"debug", HPAV_MTK_VS_FILE_ACCESS_REQ_OP_READ,
     HPAV_MTK_VS_FILE_ACCESS_REQ_FILE_TYPE_DEBUG, PARSE_NEXT_NO,
     FILE_FLAG_NONE},
    {"delete", HPAV_MTK_VS_FILE_ACCESS_REQ_OP_DELETE,
     HPAV_MTK_VS_FILE_ACCESS_REQ_FILE_TYPE_GENERAL_FILE, PARSE_NEXT_YES,
     FILE_FLAG_NONE},
    {"simage-delete", HPAV_MTK_VS_FILE_ACCESS_REQ_OP_DELETE,
     HPAV_MTK_VS_FILE_ACCESS_REQ_FILE_TYPE_SIMAGE, PARSE_NEXT_YES,
     FILE_FLAG_NONE},
    {"listdir", HPAV_MTK_VS_FILE_ACCESS_REQ_OP_LIST_DIR,
     HPAV_MTK_VS_FILE_ACCESS_REQ_FILE_TYPE_GENERAL_FILE, PARSE_NEXT_YES,
     FILE_FLAG_NONE},
    {"format", HPAV_MTK_VS_FILE_ACCESS_REQ_OP_FORMAT_FLASH,
     HPAV_MTK_VS_FILE_ACCESS_REQ_FILE_TYPE_GENERAL_FILE, PARSE_NEXT_NO,
     FILE_FLAG_NONE},
    {"save", HPAV_MTK_VS_FILE_ACCESS_REQ_OP_SAVE,
     HPAV_MTK_VS_FILE_ACCESS_REQ_FILE_TYPE_GENERAL_FILE, PARSE_NEXT_YES,
     FILE_FLAG_OUTPUT},
    {"scan-sta", HPAV_MTK_VS_FILE_ACCESS_REQ_OP_SCAN_STA,
     HPAV_MTK_VS_FILE_ACCESS_REQ_FILE_TYPE_GENERAL_FILE, PARSE_NEXT_NO,
     FILE_FLAG_NONE},
    {"", HPAV_MTK_VS_FILE_ACCESS_REQ_OP_MAX},
};

int xorchecksum(void *src, u_int32_t size, u_int32_t *chksum) {
    unsigned char *buf = src;
    unsigned char res[4] = {0};
    unsigned char cur[4];
    unsigned int offset = 0;

    if (size & 3) {
        return -1;
    }

    while (size) {
        memcpy(cur, buf + offset, 4);
        res[0] ^= cur[0];
        res[1] ^= cur[1];
        res[2] ^= cur[2];
        res[3] ^= cur[3];
        offset += 4;
        size -= 4;
    }

    res[0] = ~res[0];
    res[1] = ~res[1];
    res[2] = ~res[2];
    res[3] = ~res[3];

    memcpy(chksum, res, 4);
    return 0;
}

#define STA_LIST_FILE_NAME "sta.txt"

static hpav_mtk_vs_file_access_cnf_mstatus_t
process_mtk_vs_file_access_cnf(mtk_vs_file_access_command_t *command,
                               hpav_mtk_vs_file_access_cnf *response) {
    char *buf;
    FILE *fp = NULL;
    unsigned long long mac;
    unsigned char sta_mac[ETH_MAC_ADDRESS_SIZE];
    char sta_mac_str[32];
    hpav_mtk_vs_file_access_cnf_mstatus_t result =
        HPAV_MTK_VS_FILE_ACCESS_CNF_MSTATUS_SUCCESS;
    if (response == NULL) {
        return HPAV_MTK_FILE_ACCESS_CNF_MSTATUS_FAIL;
    }

    if (command->op == HPAV_MTK_VS_FILE_ACCESS_REQ_OP_SCAN_STA) {
        fp = fopen(STA_LIST_FILE_NAME, "w");
    }

    while (response != NULL &&
           result == HPAV_MTK_VS_FILE_ACCESS_CNF_MSTATUS_SUCCESS) {
        if (response->mstatus == HPAV_MTK_VS_FILE_ACCESS_CNF_MSTATUS_SUCCESS) {
            if (response->op == HPAV_MTK_VS_FILE_ACCESS_REQ_OP_READ ||
                response->op == HPAV_MTK_VS_FILE_ACCESS_REQ_OP_LIST_DIR) {
                buf = (char *)malloc(response->length + 1);
                memcpy(buf, response->data, response->length);
                buf[response->length] = 0;

                test_mtk_printf("%s", buf);

                if (response->total_fragments == 0 ||
                    response->fragment_number == response->total_fragments - 1)
                    test_mtk_printf("\n");

                free(buf);
            } else if (response->op ==
                       HPAV_MTK_VS_FILE_ACCESS_REQ_OP_SCAN_STA) {
                memcpy(&mac, response->data, response->length);

                mac = mac >> 16;
                mac = ((mac << 40) & 0xFF0000000000LL) |
                      ((mac << 24) & 0x00FF00000000LL) |
                      ((mac << 8) & 0x0000FF000000LL) |
                      ((mac >> 8) & 0x000000FF0000LL) |
                      ((mac >> 24) & 0x00000000FF00LL) |
                      ((mac >> 40) & 0x0000000000FFLL);
                memcpy(sta_mac, &mac, 6);
                hpav_mactos(sta_mac, sta_mac_str);
                test_mtk_printf("sta mac=%s\n", sta_mac_str);

                if (fp)
                    fprintf(fp, "%s\n", sta_mac_str);
            }

            if (response->op == HPAV_MTK_VS_FILE_ACCESS_REQ_OP_SAVE) {
                if (0 == response->fragment_number)
                    fp = fopen(command->file_name, "wb");
                else
                    fp = fopen(command->file_name, "a+b");

                if (fp) {
                    fwrite(response->data, 1, response->length, fp);
                    fclose(fp);
                }
            }

            if (response->total_fragments == 0 ||
                response->fragment_number == response->total_fragments - 1) {
                if (response->op == HPAV_MTK_VS_FILE_ACCESS_REQ_OP_WRITE ||
                    response->op == HPAV_MTK_VS_FILE_ACCESS_REQ_OP_DELETE ||
                    response->op ==
                        HPAV_MTK_VS_FILE_ACCESS_REQ_OP_FORMAT_FLASH ||
                    response->op == HPAV_MTK_VS_FILE_ACCESS_REQ_OP_SAVE) {
                    test_mtk_printf("\nSuccess\n");
                }
            }
        } else {
            test_mtk_printf("Error:%s\n", response->data);
            result = HPAV_MTK_FILE_ACCESS_CNF_MSTATUS_FAIL;
        }

        response = response->next;
    }

    if (command->op == HPAV_MTK_VS_FILE_ACCESS_REQ_OP_SCAN_STA) {
        fclose(fp);
    }
    return result;
}

static mtk_vs_file_access_command_t *parse_mtk_vs_file_access(int argc,
                                                              char *argv[]) {
    int is_parsed = 0;
    char input_output_parsed = 0;
    int idx = 0;
    mtk_vs_file_access_command_t *command = NULL;

    while (!is_parsed && idx < argc) {
        unsigned int cmd_idx = 0;
        for (command = &mtk_vs_file_access_commands[cmd_idx];
             command->op != HPAV_MTK_VS_FILE_ACCESS_REQ_OP_MAX;
             command = &mtk_vs_file_access_commands[++cmd_idx]) {
            if (strcmp(argv[idx], command->name) == 0) {
                command->parameter[0] = 0;
                command->file_name[0] = 0;
                if (command->parse_next) {
                    ++idx;
                    if (idx >= argc)
                        return NULL;

                    if (command->op == HPAV_MTK_VS_FILE_ACCESS_REQ_OP_WRITE &&
                        command->file_type ==
                            HPAV_MTK_VS_FILE_ACCESS_REQ_FILE_TYPE_SIMAGE &&
                        strcmp(argv[idx], "input") == 0) {
                        command->parameter[0] = 0;
                        idx -= 2;
                        is_parsed = 1;
                        break;
                    }

                    strcpy(command->parameter, argv[idx]);
                }
                is_parsed = 1;
                break;
            }
        }
        ++idx;
    }

    while (command->file_flag != FILE_FLAG_NONE &&
           command->op != HPAV_MTK_VS_FILE_ACCESS_REQ_OP_MAX && idx < argc) {
        input_output_parsed =
            (strcmp(argv[idx], "input") == 0)
                ? FILE_FLAG_INPUT
                : (strcmp(argv[idx], "output") == 0) ? FILE_FLAG_OUTPUT : 0;

        if (input_output_parsed) {
            ++idx;
            if (idx >= argc)
                return NULL;

            strcpy(command->file_name, argv[idx++]);
            break;
        }
        ++idx;
    }

    if (input_output_parsed != command->file_flag ||

        command->op == HPAV_MTK_VS_FILE_ACCESS_REQ_OP_MAX)
        return NULL;

    if (idx < argc && strcmp(argv[idx], "all") == 0)
        command->all_flag = 1;

    return command;
}

int test_mme_mtk_vs_file_access_req(int interface_num_to_open, int argc,
                                    char *argv[]) {
    struct hpav_if *interfaces = NULL;
    struct hpav_error *error_stack = NULL;
    struct hpav_mtk_vs_file_access_req mme_sent;
    struct hpav_mtk_vs_file_access_cnf *response;
    // Broadcast by default
    unsigned char dest_mac[ETH_MAC_ADDRESS_SIZE] = {0xFF, 0xFF, 0xFF,
                                                    0xFF, 0xFF, 0xFF};
    unsigned char tmp_dest_mac[ETH_MAC_ADDRESS_SIZE] = {0xFF, 0xFF, 0xFF,
                                                        0xFF, 0xFF, 0xFF};
    int shift_argc = 0;
    int i = 0;
    unsigned int retry_count = 0;
    unsigned char mac_result = 0;
    char mac_str[32];
    unsigned char mac_list[64][ETH_MAC_ADDRESS_SIZE];
    unsigned int sta_count = 0;
    unsigned int sta_idx = 0;

    mtk_vs_file_access_command_t *cmd = NULL;
    FILE *fp = NULL;
    unsigned int file_size = 0, remain_len, size;
    char *buf = NULL;
    int result = 0;

    if (argc == 0) {
        result = MTK_VS_FILE_ACCESS_REQ_PARAMETER_FAIL;
    } else {
        /* Check if specific mac address */
        if (!hpav_stomac(argv[0], tmp_dest_mac)) {
            printf("An error occured. Input mac value is in valid format...\n");
            return -1;
        }
        for (i = 0; i < ETH_MAC_ADDRESS_SIZE; ++i)
            mac_result |= tmp_dest_mac[i];

        if (mac_result) {
            memcpy(dest_mac, tmp_dest_mac, ETH_MAC_ADDRESS_SIZE);
            ++shift_argc;
        }
    }

    if (result == 0)
        cmd = parse_mtk_vs_file_access(argc - shift_argc, &argv[shift_argc]);

    if (result != 0 || cmd == NULL) {
        test_mtk_printf(
            "mtk_vs_file_access_req  num_interface [mac_address]\n"
            "[bootloader input BOOTLOADER]\n"
            "[simage SIMAGE input SIMAGE] [simage-delete SIMAGE_DELETE]\n"
            "[write WRITE input WRITE] [read READ] [debug]\n"
            "[save READ output OUTPUT] [delete DELETE]\n"
            "[listdir DIR] [format] [all] [scan-sta]\n");
        return MTK_VS_FILE_ACCESS_REQ_PARAMETER_FAIL;
    }

    if (cmd->all_flag) {
        fp = fopen(STA_LIST_FILE_NAME, "r");
        while (fp != NULL && fscanf(fp, "%s", mac_str) != EOF) {
            if (!hpav_stomac(mac_str, mac_list[sta_count])) {
                printf("An error occured. Input mac value is in valid format...\n");
                return -1;
            }
            ++sta_count;
        }

        fclose(fp);
    } else {
        memcpy(mac_list[sta_count], dest_mac, ETH_MAC_ADDRESS_SIZE);
        sta_count = 1;
    }

    // Get list of interfaces from libhpav
    if (hpav_get_interfaces(&interfaces, &error_stack) != HPAV_OK) {
        test_mtk_printf("An error occured. Dumping error stack...\n");
        if (!silence)
            hpav_dump_error_stack(error_stack);
        hpav_free_error_stack(&error_stack);
        return MTK_VS_FILE_ACCESS_REQ_FAIL;
    }

    if (interfaces != NULL) {
        struct hpav_if *interface_to_open = NULL;
        // Get interface
        interface_to_open =
            hpav_get_interface_by_index(interfaces, interface_num_to_open);

        // Check if an interface with this number was found
        if (interface_to_open != NULL) {
            struct hpav_chan *current_chan = NULL;
            // Open the interface
            test_mtk_printf("Opening interface %d : %s (%s)\n",
                            interface_num_to_open, interface_to_open->name,
                            (interface_to_open->description != NULL
                                 ? interface_to_open->description
                                 : "no description"));

            current_chan = hpav_open_channel(interface_to_open, &error_stack);

            if (current_chan != NULL) {
                test_mtk_printf("Interface successfully opened\n");
                for (sta_idx = 0; sta_idx < sta_count; ++sta_idx) {
                    retry_count = 0;
                    memcpy(dest_mac, mac_list[sta_idx], ETH_MAC_ADDRESS_SIZE);
                    memset(&mme_sent, 0, sizeof(mme_sent));
                    mme_sent.op = cmd->op;
                    mme_sent.file_type = cmd->file_type;
                    if (strlen(cmd->parameter) >
                        HPAV_MTK_VS_FILE_ACCESS_PARAMETER_MAX_LEN) {
                        test_mtk_printf("The length of parameter of "
                                        "vs_file_acceess.req is too long\n");
                        result = MTK_VS_FILE_ACCESS_REQ_PARAMETER_FAIL;
                        return result;
                    } else if (strlen(cmd->parameter) != 0)
                        strcpy(mme_sent.parameter, cmd->parameter);

                    if (cmd->op == HPAV_MTK_VS_FILE_ACCESS_REQ_OP_WRITE) {
                        fp = fopen(cmd->file_name, "rb");
                        if (fp == NULL) {
                            test_mtk_printf("Can't open the file - %s\n",
                                            cmd->file_name);
                            result = MTK_VS_FILE_ACCESS_REQ_FAIL;
                            return result;
                        }

                        fseek(fp, 0, SEEK_END);
                        file_size = ftell(fp);
                        rewind(fp);

                        buf = (char *)malloc(file_size);
                        fread(buf, 1, file_size, fp);
                        fclose(fp);

                        mme_sent.total_fragments =
                            (file_size +
                             HPAV_MTK_VS_FILE_ACCESS_REQ_DATA_MAX_LEN - 1) /
                            (HPAV_MTK_VS_FILE_ACCESS_REQ_DATA_MAX_LEN);
                    }

                    // Sending MME on the channel
                    test_mtk_printf("Sending MStar VS_FILE_ACCESS.REQ %s : "
                                    "%s on the channel\n",
                                    hpav_mactos(dest_mac, mac_str), cmd->name);

                    do {
                        if (cmd->op == HPAV_MTK_VS_FILE_ACCESS_REQ_OP_WRITE) {
                            remain_len =
                                file_size -
                                (HPAV_MTK_VS_FILE_ACCESS_REQ_DATA_MAX_LEN *
                                 mme_sent.fragment_number);
                            size =
                                (remain_len >
                                 HPAV_MTK_VS_FILE_ACCESS_REQ_DATA_MAX_LEN)
                                    ? HPAV_MTK_VS_FILE_ACCESS_REQ_DATA_MAX_LEN
                                    : remain_len;

                            memcpy(
                                mme_sent.data,
                                buf +
                                    (HPAV_MTK_VS_FILE_ACCESS_REQ_DATA_MAX_LEN *
                                     (mme_sent.fragment_number)),
                                size);

                            mme_sent.length = size;
                            mme_sent.offset =
                                HPAV_MTK_VS_FILE_ACCESS_REQ_DATA_MAX_LEN *
                                (mme_sent.fragment_number);

                            if (cmd->file_type !=
                                HPAV_MTK_VS_FILE_ACCESS_REQ_FILE_TYPE_GENERAL_FILE) {
                                xorchecksum(
                                    buf +
                                        (HPAV_MTK_VS_FILE_ACCESS_REQ_DATA_MAX_LEN *
                                         (mme_sent.fragment_number)),
                                    mme_sent.length, &mme_sent.checksum);
                            }
                        }
                        result = hpav_mtk_vs_file_access_sndrcv(
                            current_chan, dest_mac, &mme_sent, &response, 5000,
                            0, &error_stack,
                            cmd->op == HPAV_MTK_VS_FILE_ACCESS_REQ_OP_SCAN_STA);
                        if (result != HPAV_OK) {
                            test_mtk_printf(
                                "An error occured. Dumping error stack...\n");
                            if (!silence)
                                hpav_dump_error_stack(error_stack);
                            hpav_free_error_stack(&error_stack);
                            result = -1;
                        }

                        else if (response != NULL) {
                            hpav_mtk_vs_file_access_cnf_mstatus_t cnf_result =
                                process_mtk_vs_file_access_cnf(cmd, response);
                            if (cnf_result ==
                                HPAV_MTK_FILE_ACCESS_CNF_MSTATUS_FAIL) {
                                test_mtk_printf("An error occured. Dumping "
                                                "error stack...\n");
                                if (!silence)
                                    hpav_dump_error_stack(error_stack);
                                hpav_free_error_stack(&error_stack);
                                result = HPAV_NOK;
                            }
                            memcpy(dest_mac, response->sta_mac_addr,
                                   ETH_MAC_ADDRESS_SIZE);
                            mme_sent.total_fragments =
                                response->total_fragments;
                            mme_sent.fragment_number =
                                response->fragment_number + 1;

                            if (cmd->op ==
                                    HPAV_MTK_VS_FILE_ACCESS_REQ_OP_WRITE ||
                                response->op ==
                                    HPAV_MTK_VS_FILE_ACCESS_REQ_OP_SAVE) {
                                if (retry_count == 0 &&
                                    response->fragment_number % 10 == 0)
                                    test_mtk_printf("=");
                            }
                            retry_count = 0;
                        } else {
                            ++retry_count;
                            if (retry_count >= 3) {
                                test_mtk_printf(
                                    "Timeout:maximum retry %d times\n",
                                    retry_count);
                                result = MTK_VS_FILE_ACCESS_REQ_FAIL;
                                break;
                            }
                        }
                    } while (
                        result == HPAV_OK &&
                        ((mme_sent.total_fragments == 0 && response == NULL) ||
                         mme_sent.fragment_number < mme_sent.total_fragments));

                    if (buf != NULL)
                        free(buf);

                    test_mtk_printf("\n");
                }

                // Free response
                hpav_free_mtk_vs_file_access_cnf(response);

                // Close channel
                hpav_close_channel(current_chan);
                test_mtk_printf("Interface closed\n");
            } else {
                test_mtk_printf("Error while opening the interface\n");
                if (!silence)
                    hpav_dump_error_stack(error_stack);
                hpav_free_error_stack(&error_stack);
                result = MTK_VS_FILE_ACCESS_REQ_FAIL;
            }
        } else {
            unsigned int num_interfaces =
                hpav_get_number_of_interfaces(interfaces);
            test_mtk_printf("Interface number %d not found (0-%d available)\n",
                            interface_num_to_open, (num_interfaces - 1));
            result = MTK_VS_FILE_ACCESS_REQ_FAIL;
        }
        // Free list of interfaces
        hpav_free_interfaces(interfaces);
    } else {
        test_mtk_printf("No interface available\n");
        result = MTK_VS_FILE_ACCESS_REQ_FAIL;
    }
    return result;
}
