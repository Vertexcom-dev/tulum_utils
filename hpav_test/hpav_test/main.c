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
#include "exitcodes.h"

#include <stdarg.h>
#include <stdbool.h>


#define FCT_NAME_ENTRY(name, fct)                                              \
    { fct, #name }
struct fct_name_t {
    int (*fct)(int argc, char *argv[]);
    char name[20];
};

#define TEST_MME_FCT_NAME_ENTRY(name)                                          \
    { test_mme_##name, #name }
struct test_mme_fct_name_t {
    int (*fct)(hpav_chan_t *channel, int argc, char *argv[]);
    char name[60];
};

// Opens a channel on given interface (can be interface number or name)
// On success, channel is populated and zero is returned; otherwise a non-zero
// return value is used to indicate an error.
int open_channel(char *if_name_or_index, hpav_chan_t **channel) {
    struct hpav_error *error_stack;
    struct hpav_if *interfaces, *iface;
    bool was_index = false;
    unsigned int if_num;
    int rv = 0;

    // Get list of interfaces from libhpav
    if (hpav_get_interfaces(&interfaces, &error_stack) != HPAV_OK) {
        printf("An error occurred. Dumping error stack...\n");
        hpav_dump_error_stack(error_stack);
        hpav_free_error_stack(&error_stack);
        return -1;
    }

    if (interfaces == NULL) {
        printf("No interface available\n");
        return 0;
    }

    // Get interface
    iface = hpav_get_interface_by_index_or_name(interfaces, if_name_or_index,
                                                &was_index, &if_num);
    if (iface == NULL) {
        if (was_index) {
            unsigned int num_interfaces =
                hpav_get_number_of_interfaces(interfaces);
            printf("Interface number %s not found (0-%d available)\n",
                   if_name_or_index, num_interfaces - 1);
        } else {
            printf("Interface '%s' not found. Use 'hpav_test list_if' to list available ones.\n",
                   if_name_or_index);
        }
        rv = EXIT_USAGE;
        goto free_out;
    }

    // Open the interface
    printf("Opening interface %d : %s (%s)\n", if_num, iface->name,
           iface->description ? iface->description : "no description");
    *channel = hpav_open_channel(iface, &error_stack);
    if (*channel == NULL) {
        printf("Error while opening the interface\n");
        hpav_dump_error_stack(error_stack);
        hpav_free_error_stack(&error_stack);
        rv = EXIT_FAILURE;
        goto free_out;
    }

    printf("Interface successfully opened\n");

free_out:
    // Free list of interfaces
    hpav_free_interfaces(interfaces);
    return rv;
}

void close_channel(hpav_chan_t *channel) {
    // Close channel
    hpav_close_channel(channel);
    printf("Interface closed\n");
}

int execute_on_channel(char *if_name_or_index,
                       int (*fct)(hpav_chan_t *channel, int argc, char *argv[]),
                       int argc, char *argv[]) {
    hpav_chan_t *channel;
    int rv;

    rv = open_channel(if_name_or_index, &channel);
    if (rv)
        return rv;

    // we call the function only if given -> so we can support 'open_if' command
    if (fct)
        rv = fct(channel, argc, argv);

    close_channel(channel);
    return rv;
}

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
        printf("An error occurred. Dumping error stack...\n");
        // An error occurred, dump error_stack
        hpav_dump_error_stack(error_stack);
        // return with error
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

// Open given interface
int open_interface(int argc, char *argv[]) {
    // This is the first and only argument
    if (argc != 1) {
        printf("Usage : hpav_test open_if interface\n\ninterface can be name or"
               " number (which starts at 0), see 'hpav_test list_if'\n");
        return EXIT_USAGE;
    }

    return execute_on_channel(argv[0], NULL, 0, NULL);
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
                return execute_on_channel(argv[1],
                                          test_mme_fct_name_table[i].fct,
                                          argc - 2, &argv[2]);
            }
        }
    }

    printf("Usage : hpav_test test_mme mme_name(partial or full) interface "
           "[mac_address [parameters]]\n");
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
    return EXIT_USAGE;
}

int test_secu(int argc, char *argv[]) {
    int rv = EXIT_USAGE;
    if (argc > 1) {
        if (strcmp(argv[0], "gen_nmk") == 0) {
            rv = test_secu_gen_nmk(argc - 1, &argv[1]);
        } else if (strcmp(argv[0], "gen_dak") == 0) {
            rv = test_secu_gen_dak(argc - 1, &argv[1]);
        } else if (strcmp(argv[0], "gen_nid") == 0) {
            rv = test_secu_gen_nid(argc - 1, &argv[1]);
        } else {
            goto print_usage;
        }
    } else if (argc == 1 && strcmp(argv[0], "encrypt") == 0) {
        rv = test_secu_encrypt(argc - 1, &argv[1]);
    } else {
print_usage:
        printf("Usage : hpav_test test_secu gen_nmk|gen_dak|gen_nid|encrypt "
               "input [security_level]\n");
    }
    return rv;
}

int conf_file(int argc, char *argv[]) {
    test_mme_mtk_printf_silence();
    if (argc >= 1) {
        if (strcmp(argv[0], "read") == 0) {
            if (argc >= 2)
                return execute_on_channel(argv[1], conf_file_read, argc - 2, &argv[2]);

            printf("Usage : hpav_test conf_file read interface filename [mac_address]\n");
        } else if (strcmp(argv[0], "write") == 0) {
            if (argc >= 2)
                return execute_on_channel(argv[1], conf_file_write, argc - 2, &argv[2]);

            printf("Usage : hpav_test conf_file write interface filename [mac_address]\n");
        } else if (strcmp(argv[0], "parse") == 0) {
            return conf_file_parse(argc - 1, &argv[1]);
        } else if (strcmp(argv[0], "modify") == 0) {
            return conf_file_modify(argc - 1, &argv[1]);
        }
    } else {
        printf("Usage : hpav_test conf_file read|write|parse|modify\n");
    }
    return EXIT_USAGE;
}

int test_nvram(int argc, char *argv[]) {
    if (argc >= 1) {
        if (strcmp(argv[0], "read") == 0) {
            if (argc >= 2)
                return execute_on_channel(argv[1], test_nvram_read, argc - 2, &argv[2]);

            printf("Usage: $hpav_test nvram read interface mac output_file\n");
        } else if (strcmp(argv[0], "write") == 0) {
            if (argc >= 2)
                return execute_on_channel(argv[1], test_nvram_write, argc - 2, &argv[2]);

            printf("Usage: $hpav_test nvram write interface mac input_file\n");
        } else if (strcmp(argv[0], "parse") == 0) {
            return test_nvram_parse(argc - 1, &argv[1]);
        } else if (strcmp(argv[0], "modify") == 0) {
            return test_nvram_modify(argc - 1, &argv[1]);
        }
    } else {
        printf("Usage : hpav_test nvram read|write|parse|modify\n");
    }
    return EXIT_USAGE;
}

int test_reboot(int argc, char *argv[]) {
    if (argc > 0 && argc < 2) {
        return execute_on_channel(argv[0],
                                  test_mme_mtk_vs_reset_req,
                                  argc - 1, &argv[1]);
    }
    printf("Usage: hpav_test reboot interface [mac]\n");
    return EXIT_USAGE;
}

int test_find_local_sta(int argc, char *argv[]) {
    struct hpav_error *error_stack = NULL;
    struct hpav_if *interfaces = NULL;
    struct hpav_if *current_interface = NULL;
    int rv = EXIT_SUCCESS;

    if (argc > 1) {
        printf("Usage: hpav_test find_local_sta [interface]\n");
        return EXIT_USAGE;
    }

    if (argc == 1) {
        return execute_on_channel(argv[0],
                                  test_mme_mtk_vs_get_nw_info_req,
                                  argc - 1, &argv[1]);
    }

    // Get list of interfaces from libhpav
    if (hpav_get_interfaces(&interfaces, &error_stack) != HPAV_OK) {
        printf("An error occurred. Dumping error stack...\n");
        hpav_dump_error_stack(error_stack);
        hpav_free_error_stack(&error_stack);
        return EXIT_FAILURE;
    }

    if (interfaces == NULL) {
        printf("No interface available\n");
        return EXIT_SUCCESS;
    }

    current_interface = interfaces;
    while (current_interface != NULL) {
        int result =
            execute_on_channel(current_interface->name,
                               test_mme_mtk_vs_get_nw_info_req,
                               argc - 1, &argv[1]);
        // remember error for exit code, but continue
        if (result)
            rv = EXIT_FAILURE;
        current_interface = current_interface->next;
    }

    hpav_free_interfaces(interfaces);
    return rv;
}

int test_fw_upgrade(int argc, char *argv[]) {
    if (argc == 4) {
        int result = 0;
        char *param[5];
        param[0] = argv[1];
        param[1] = "bootloader";
        param[2] = "input";
        param[3] = argv[2];
        result = execute_on_channel(argv[0], test_mme_mtk_vs_file_access_req, 4, &param[0]);
        if (result)
            return result;
        param[1] = "simage";
        param[2] = argv[3];
        param[3] = "input";
        param[4] = argv[3];
        result = execute_on_channel(argv[0], test_mme_mtk_vs_file_access_req, 5, &param[0]);
        return result;
    }
    printf("Usage: hpav_test fw_upgrade interface mac bootloader firmware\n");
    return EXIT_USAGE;
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
                int rv =
                    main_fct_name_table[i].fct(argc - 2, &argv[2]);
                // clamp to general error
                if (rv < 0)
                  rv = EXIT_FAILURE;
                return rv;
            }

    printf("HPAV_TEST - %s\n", hpav_full_release_name);
    if (argc > 1)
        printf("  Unknown command : %s\n", argv[1]);

    // Help for user.
    printf("\nCommands are :\n");
    for (i = nb_fct; i >= 0; i--)
        printf("   %s\n", main_fct_name_table[i].name);

    return EXIT_USAGE;
}
