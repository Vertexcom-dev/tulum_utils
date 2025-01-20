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
#include "hpav_api.h"
#include "hpav_mtk_api.h"
#include "hpav_utils.h"
#include "hpav_version.h"
#include "util.h"
#include "test_hpav.h"
#include "test_security.h"
#include "test_mtk.h"
#include "test_nvram.h"
#include "conf_file.h"

#include <stdarg.h>

#define FCT_NAME_ENTRY(name, fct)                                              \
    { fct, #name }
struct fct_name_t {
    int (*fct)(int argc, char *argv[]);
    char name[20];
};

#define TEST_MME_FCT_NAME_ENTRY(name)                                          \
    { test_mme_##name, #name }
struct test_mme_fct_name_t {
    int (*fct)(int interface_num_to_open, int argc, char *argv[]);
    char name[60];
};

// List available interfaces
int list_interfaces(int argc, char *argv[]) {
    // Get list of interfaces from libhpav
    struct hpav_if *interfaces = NULL;
    struct hpav_error *error_stack = NULL;
    if (hpav_get_interfaces(&interfaces, &error_stack) == HPAV_OK) {
        if (interfaces != NULL) {
            // Dump interfaces
            dump_interfaces(interfaces);
            // Free list of interfaces
            hpav_free_interfaces(interfaces);
        } else {
            printf("No interfaces available\n");
        }
    } else {
        printf("An error occured. Dumping error stack...\n");
        // An error occured, dump error_stack
        hpav_dump_error_stack(error_stack);
    }
    return 0;
}

// Open given interface
int open_interface(int argc, char *argv[]) {
    // The interface to open is a number from 0 to n-1 (n interfaces returned by
    // hpav_get_interfaces)
    struct hpav_if *interfaces = NULL;
    struct hpav_error *error_stack = NULL;
    int interface_num_to_open = -1;
    // This is the first and only argument
    if (argc != 1) {
        printf("Usage : hpav_test open_if interface_number\n(starts at 0)\n");
        return -1;
    }

    // Get interface number
    interface_num_to_open = atoi(argv[0]);

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
                printf("Interface successfully opened\n");
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
                   interface_num_to_open, num_interfaces - 1);
        }
        // Free list of interfaces
        hpav_free_interfaces(interfaces);
    } else {
        printf("No interface available\n");
    }
    return 0;
}

static const struct test_mme_fct_name_t test_mme_fct_name_table[] = {
    TEST_MME_FCT_NAME_ENTRY(cm_set_key_req),
    TEST_MME_FCT_NAME_ENTRY(cm_amp_map_req),
    TEST_MME_FCT_NAME_ENTRY(mtk_vs_get_version_req),
    TEST_MME_FCT_NAME_ENTRY(mtk_vs_reset_req),
    TEST_MME_FCT_NAME_ENTRY(mtk_vs_get_tonemask_req),
    TEST_MME_FCT_NAME_ENTRY(mtk_vs_get_eth_phy_req),
    TEST_MME_FCT_NAME_ENTRY(mtk_vs_eth_stats_req),
    TEST_MME_FCT_NAME_ENTRY(mtk_vs_get_status_req),
    TEST_MME_FCT_NAME_ENTRY(mtk_vs_get_tonemap_req),
    TEST_MME_FCT_NAME_ENTRY(mtk_vs_get_snr_req),
    TEST_MME_FCT_NAME_ENTRY(mtk_vs_get_link_stats_req),
    TEST_MME_FCT_NAME_ENTRY(mtk_vs_get_nw_info_req),
    TEST_MME_FCT_NAME_ENTRY(mtk_vs_set_capture_state_req),
    TEST_MME_FCT_NAME_ENTRY(mtk_vs_set_nvram_req),
    TEST_MME_FCT_NAME_ENTRY(mtk_vs_get_nvram_req),
    TEST_MME_FCT_NAME_ENTRY(mtk_vs_get_pwm_stats_req),
    TEST_MME_FCT_NAME_ENTRY(mtk_vs_get_pwm_conf_req),
    TEST_MME_FCT_NAME_ENTRY(mtk_vs_set_pwm_conf_req),
    TEST_MME_FCT_NAME_ENTRY(mtk_vs_pwm_generation_req),
    TEST_MME_FCT_NAME_ENTRY(mtk_vs_spi_stats_req),
    TEST_MME_FCT_NAME_ENTRY(mtk_vs_set_tx_cali_req),
    TEST_MME_FCT_NAME_ENTRY(vc_vs_set_sniffer_conf_req),
    TEST_MME_FCT_NAME_ENTRY(vc_vs_set_remote_access_req),
    TEST_MME_FCT_NAME_ENTRY(vc_vs_get_remote_access_req),
    TEST_MME_FCT_NAME_ENTRY(mtk_vs_file_access_req),
};
// Send a mme to given interface
// Number of parameters depends on the type of MME
int test_mme(int argc, char *argv[]) {
    int nb_fct =
        (sizeof(test_mme_fct_name_table) / sizeof(struct test_mme_fct_name_t));
    int i;
    int filter = argc > 0 ? 1 : 0;
    int newLine = 0;

    if ((argc > 1) && (1 <= strlen(argv[1]))) {
        for (i = nb_fct; i >= 0; i--) {
            if (strcmp(argv[0], test_mme_fct_name_table[i].name) == 0) {
                test_mme_fct_name_table[i].fct(atoi(argv[1]), argc - 2,
                                               &argv[2]);
                return 0;
            }
        }
    }

    printf("Usage : hpav_test test_mme mme_name(partial or full) interface "
           "number [mac_address [parameters]]\n");
    printf("\nmme_name can be :\n   ");
    for (i = 0; i < nb_fct; i++) {
        if (filter) {
            if (strstr(test_mme_fct_name_table[i].name, argv[0])) {
                if (newLine % 2 == 0)
                    printf("\n   ");
                newLine++;
                printf("%-30s", test_mme_fct_name_table[i].name);
            }
        } else {
            if (newLine % 2 == 0)
                printf("\n   ");
            newLine++;
            printf("%-30s\t", test_mme_fct_name_table[i].name);
        }
    }
    printf("\n");
    return 0;
}

int test_secu(int argc, char *argv[]) {
    if (argc > 1) {
        if (strcmp(argv[0], "gen_nmk") == 0) {
            test_secu_gen_nmk(argc - 1, &argv[1]);
        } else if (strcmp(argv[0], "gen_dak") == 0) {
            test_secu_gen_dak(argc - 1, &argv[1]);
        } else if (strcmp(argv[0], "gen_nid") == 0) {
            test_secu_gen_nid(argc - 1, &argv[1]);
        }
    } else if (argc == 1 && strcmp(argv[0], "encrypt") == 0) {
        test_secu_encrypt(argc - 1, &argv[1]);
    } else {
        printf("Usage : hpav_test test_secu gen_nmk|gen_dak|gen_nid|encrypt "
               "input [security_level]\n");
    }
    return 0;
}

int conf_file(int argc, char *argv[]) {
    test_mme_mtk_printf_silence();
    if (argc >= 1) {
        if (strcmp(argv[0], "read") == 0) {
            conf_file_read(argc - 1, &argv[1]);
        } else if (strcmp(argv[0], "write") == 0) {
            conf_file_write(argc - 1, &argv[1]);
        } else if (strcmp(argv[0], "parse") == 0) {
            conf_file_parse(argc - 1, &argv[1]);
        } else if (strcmp(argv[0], "modify") == 0) {
            conf_file_modify(argc - 1, &argv[1]);
        }
        return 0;
    }
    printf("Usage : hpav_test conf_file read|write|parse|modify\n");
    return 0;
}

int test_nvram(int argc, char *argv[]) {
    if (argc >= 1) {
        if (strcmp(argv[0], "read") == 0) {
            test_nvram_read(argc - 1, &argv[1]);
        } else if (strcmp(argv[0], "write") == 0) {
            test_nvram_write(argc - 1, &argv[1]);
        } else if (strcmp(argv[0], "parse") == 0) {
            test_nvram_parse(argc - 1, &argv[1]);
        } else if (strcmp(argv[0], "modify") == 0) {
            test_nvram_modify(argc - 1, &argv[1]);
        } else {
            printf("Usage: hpav_test nvram read | write | parse | modify\n");
        }


        return 0;
    }
    printf("Usage: hpav_test nvram read | write | parse | modify\n");
    return 0;
}

int test_reboot(int argc, char *argv[]) {
    if (argc >= 1) {
        int interface_num_to_open = atoi(argv[0]);
        struct hpav_if *interfaces = NULL;
        struct hpav_error *error_stack = NULL;

        if (hpav_get_interfaces(&interfaces, &error_stack) != HPAV_OK) {
            printf("An error occured. Dumping error stack...\n");
            hpav_dump_error_stack(error_stack);
            hpav_free_error_stack(&error_stack);
            return -1;
        }

        if (interfaces != NULL) {
            struct hpav_if *interface_to_open = NULL;
            interface_to_open =
                hpav_get_interface_by_index(interfaces, interface_num_to_open);

            if (interface_to_open != NULL) {
                struct hpav_chan *current_chan = NULL;
                current_chan =
                    hpav_open_channel(interface_to_open, &error_stack);
                if (current_chan != NULL) {
                    int result = -1;
                    struct hpav_mtk_vs_reset_req mme_sent;
                    struct hpav_mtk_vs_reset_cnf *response;
                    unsigned char dest_mac[ETH_MAC_ADDRESS_SIZE] = {
                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
                    if (argc >= 2) {
                        if (!hpav_stomac(argv[1], dest_mac)) {
                            printf("An error occured. Input mac value is in valid format...\n");
                            return -1;
                        }
                    }
                    else {
                        unsigned char link_local_mac[ETH_MAC_ADDRESS_SIZE] = {
                            0x0, 0x13, 0xD7, 0x0, 0x0, 0x01};
                        memcpy(dest_mac, link_local_mac, 6);
                    }

                    result = hpav_mtk_vs_reset_sndrcv(current_chan, dest_mac,
                                                        &mme_sent, &response,
                                                        1000, 0, &error_stack);
                    if (result != HPAV_OK) {
                        printf("An error occured. Dumping error stack...\n");
                        hpav_dump_error_stack(error_stack);
                        hpav_free_error_stack(&error_stack);
                    }
                    else {
                        int sta_num = 1;
                        if (response == NULL) {
                            printf("No STA answered\n\n");
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

                    hpav_free_mtk_vs_reset_cnf(response);
                    hpav_close_channel(current_chan);
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
            hpav_free_interfaces(interfaces);
        } else
            printf("No interface available\n");
        return 0;
    }
    printf("Usage: hpav_test reboot if_num [mac]\n");
    return 0;
}

int test_find_local_sta(int argc, char *argv[]) {
    if (0 <= argc && argc <= 1) {
        struct hpav_if *interfaces = NULL;
        struct hpav_error *error_stack = NULL;
        struct hpav_chan *current_chan = NULL;
        struct hpav_if *interface_to_open = NULL;
        int interface_num_to_open = 0;
        struct hpav_mtk_vs_get_nw_info_req mme_sent;
        struct hpav_mtk_vs_get_nw_info_cnf *response;
        unsigned char dest_mac[ETH_MAC_ADDRESS_SIZE] = {0xff, 0xff, 0xff,
                                                        0xff, 0xff, 0xff};
        unsigned int i = 0;
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

        // Get overall count of available interfaces
        unsigned int if_number = hpav_get_number_of_interfaces(interfaces);

        // In case optional parameter if_num is given, just operate on that
        if (argc == 1) {
            // Get interface number
            interface_num_to_open = atoi(argv[0]);
            // Check that interface number does not exceed available interface numbers
            if (interface_num_to_open < 0 || interface_num_to_open >= if_number) {
                printf("Interface number %d not found (0-%d available)\n",
                       interface_num_to_open, if_number - 1);
                return -1;
            }
            // Adjust limit for loop
            if_number = interface_num_to_open + 1;
        }

        for (i = interface_num_to_open; i < if_number; i++) {
            // Get interface
            interface_to_open = hpav_get_interface_by_index(interfaces, i);

            printf("\nOpening interface %d : %s (%s)\n", i,
                   interface_to_open->name,
                   (interface_to_open->description != NULL
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
            memset(&mme_sent, 0x0,
                   sizeof(struct hpav_mtk_vs_get_nw_info_req));
            result = hpav_mtk_vs_get_nw_info_sndrcv(current_chan, dest_mac,
                                                      &mme_sent, &response,
                                                      1000, 0, &error_stack);
            if (result != HPAV_OK) {
                printf("An error occured. Dumping error stack...\n");
                hpav_dump_error_stack(error_stack);
                hpav_free_error_stack(&error_stack);
            } else {
                if (NULL == response) {
                    printf("No STA answered\n\n");
                }
                int sta_num = 1;
                while (response != NULL)
                {
                    char buffer[64];
                    printf("Station %d :\n", sta_num);
                    printf("MAC address                                           : %s\n",
                        hpav_mactos(response->sta_mac_addr, buffer));
                    sta_num++;
                    response = response->next;
                }
            }

            // Free response
            hpav_free_mtk_vs_get_nw_info_cnf(response);
            // Close channel
            hpav_close_channel(current_chan);
            printf("Interface closed\n");
        }

        // Free list of interfaces
        hpav_free_interfaces(interfaces);

        return 0;
    }
    printf("Usage: hpav_test find_local_sta [if_num]\n");
    return 0;
}

int test_fw_upgrade(int argc, char *argv[]) {
    if (argc == 4) {
        int result = 0;
        char *param[5];
        param[0] = argv[1];
        param[1] = "bootloader";
        param[2] = "input";
        param[3] = argv[2];
        result = test_mme_mtk_vs_file_access_req(atoi(argv[0]), 4, &param[0]);
        param[1] = "simage";
        param[2] = argv[3];
        param[3] = "input";
        param[4] = argv[3];
        result = test_mme_mtk_vs_file_access_req(atoi(argv[0]), 5, &param[0]);
        return result;
    }
    printf("Usage: hpav_test fw_upgrade if_num mac bootloader firmware\n");
    return 0;
}
static const struct fct_name_t main_fct_name_table[] = {
    FCT_NAME_ENTRY(list_if, list_interfaces),
    FCT_NAME_ENTRY(open_if, open_interface),
    FCT_NAME_ENTRY(test_mme, test_mme),
    FCT_NAME_ENTRY(test_secu, test_secu),
    FCT_NAME_ENTRY(conf_file, conf_file),
    FCT_NAME_ENTRY(nvram, test_nvram),
    FCT_NAME_ENTRY(reboot, test_reboot),
    FCT_NAME_ENTRY(find_local_sta, test_find_local_sta),
    FCT_NAME_ENTRY(fw_upgrade, test_fw_upgrade),
};

int main(int argc, char *argv[]) {
    int nb_fct = (sizeof(main_fct_name_table) / sizeof(struct fct_name_t)) - 1;
    int i = 0;

    if (argc > 1)
        for (i = nb_fct; i >= 0; i--)
            if (strcmp(argv[1], main_fct_name_table[i].name) == 0) {
                main_fct_name_table[i].fct(argc - 2, &argv[2]);
                return 0;
            }

    printf("HPAV_TEST - %s\n", hpav_full_release_name);
    if (argc > 1)
        printf("  Unknown command : %s\n", argv[1]);

    // Help for user.
    printf("\nCommands are :\n");
    for (i = nb_fct; i >= 0; i--)
        printf("   %s\n", main_fct_name_table[i].name);

    return 0;
}
