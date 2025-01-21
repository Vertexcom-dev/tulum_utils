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
#include "conf_file.h"
#include "test_mtk.h"
#include "hpav_api.h"
#include "hpav_utils.h"
#include "parson.h"
#include "stdbool.h"
#include "stdio.h"
#include "exitcodes.h"

#ifdef WIN32
#include "windows.h"
#else
#include "unistd.h"
#endif

#define MTK_LINK_LOCAL_ADDR "00:13:d7:00:00:01"
#define DEVICE_INKA_CONF_PATH "/inka.conf"
#define DEVICE_INKA_UPDATE_CONF_PATH "/inka_update.conf"
#define PSD_Notched 15
typedef struct {
    int startCarrier;
    int endCarrier;
} NotchCarrierRange;

int conf_file_read(int argc, char *argv[]) {
    char *param[5];
    bool inka_update_exist = false;
    do {
        int rv = 0;
        if ((argc < 2) || (1 != strlen(argv[0])))
            break;
        /** Read inka.conf. */
        if (argc > 2)
            param[0] = argv[2];
        else
            param[0] = MTK_LINK_LOCAL_ADDR;
        param[1] = "save";
        param[2] = DEVICE_INKA_CONF_PATH;
        param[3] = "output";
        param[4] = "inka.conf.tmp";
        if (test_mme_mtk_vs_file_access_req(atoi(argv[0]), 5, &param[0]) !=
            0) {
            printf("Failed : read inka.conf!\n");
            return -1;
        }
        /** Try to read inka_update.conf. inka_update.conf may not exist. */
        param[2] = DEVICE_INKA_UPDATE_CONF_PATH;
        param[4] = "inka_update.conf.tmp";
        if (test_mme_mtk_vs_file_access_req(atoi(argv[0]), 5, &param[0]) == 0)
            inka_update_exist = true;
        JSON_Value *inka = json_parse_file("inka.conf.tmp");
        /** Merge inka.conf and inka_update.conf if needed. */
        if (inka_update_exist) {
            JSON_Value *inka_update = json_parse_file("inka_update.conf.tmp");
            if (JSONSuccess != json_value_merge(inka, inka_update)) {
                printf("Failed : JSON merge!\n");
                remove("inka.conf.tmp");
                remove("inka_update.conf.tmp");
                return -1;
            }
        }
        if (JSONSuccess != json_serialize_to_file(inka, argv[1])) {
            printf("Failed : JSON to file!\n");
            rv = -1;
        }
        remove("inka.conf.tmp");
        remove("inka_update.conf.tmp");
        return rv;
    } while (0);
    printf("Usage : hpav_test conf_file read if_num filename [mac_address]\n");
    return EXIT_USAGE;
}

int conf_file_write(int argc, char *argv[]) {
    char *param[5];
    do {
        if ((argc < 2) || (1 != strlen(argv[0])))
            break;
        /** Try to delete inka_update.conf. */
        if (argc >= 3)
            param[0] = argv[2];
        else
            param[0] = MTK_LINK_LOCAL_ADDR;
        param[1] = "delete";
        param[2] = DEVICE_INKA_UPDATE_CONF_PATH;
        test_mme_mtk_vs_file_access_req(atoi(argv[0]), 3, &param[0]);
        /** Write file to device. */
        param[1] = "write";
        param[2] = DEVICE_INKA_CONF_PATH;
        param[3] = "input";
        param[4] = argv[1];
        if (test_mme_mtk_vs_file_access_req(atoi(argv[0]), 5, &param[0]) != 0) {
            printf("Failed : write inka.conf!\n");
            return -1;
        }
        return 0;
    } while (0);
    printf("Usage : hpav_test conf_file write if_num filename [mac_address]\n");
    return EXIT_USAGE;
}

static void conf_file_parse_version(JSON_Object *object, int *version,
                                    int *sub_version) {
    *version = (int)json_object_get_number(object, "version");
    *sub_version = (int)json_object_get_number(object, "sub_version");
    printf("Version                                              : ");
    printf("%u.%u\n", *version, *sub_version);
}

static void conf_file_parse_mac(JSON_Object *object) {
    unsigned long long value;
    value = (unsigned long long)json_object_get_number(object, "mac");
    printf("MAC Address                                          : ");
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n",
           (unsigned int)((value & 0xff0000000000) >> 40),
           (unsigned int)((value & 0x00ff00000000) >> 32),
           (unsigned int)((value & 0x0000ff000000) >> 24),
           (unsigned int)((value & 0x000000ff0000) >> 16),
           (unsigned int)((value & 0x00000000ff00) >> 8),
           (unsigned int)(value & 0x0000000000ff));
}

static void conf_file_parse_nmk(JSON_Object *object) {
    JSON_Array *array;
    printf("NMK                                                  : ");
    array = json_object_get_array(object, "nmk");
    if (!array) {
        printf("parse failed!\n");
    } else {
        int i;
        for (i = 0; i < 4; i++) {
            unsigned int nmk;
            nmk = (unsigned int)json_array_get_number(array, i);
            printf("%02X:%02X:%02X:%02X", (nmk & 0x000000ff),
                   (nmk & 0x0000ff00) >> 8, (nmk & 0x00ff0000) >> 16,
                   (nmk & 0xff000000) >> 24);
            if (i == 3)
                printf("\n");
            else
                printf(":");
        }
    }
}

static void conf_file_parse_nid(JSON_Object *object) {
    unsigned long long value;
    printf("Network ID                                           : ");
    value = (unsigned long long)json_object_get_number(object, "nid");
    if (value == 0)
        printf("auto-gen by NMK\n");
    else {
        printf("%02X:%02X:%02X:%02X:%02X:%02X:%02X\n",
               (unsigned int)(value & 0x00000000000000ff),
               (unsigned int)((value & 0x000000000000ff00) >> 8),
               (unsigned int)((value & 0x0000000000ff0000) >> 16),
               (unsigned int)((value & 0x00000000ff000000) >> 24),
               (unsigned int)((value & 0x000000ff00000000) >> 32),
               (unsigned int)((value & 0x0000ff0000000000) >> 40),
               (unsigned int)((value & 0x00ff000000000000) >> 48));
    }
}

static void conf_file_parse_role(JSON_Object *object) {
    printf("Role(cco : EVSE, sta : PEV)                          : %s\n",
           json_object_get_string(object, "force_role"));
}

static void conf_file_parse_hfids(JSON_Object *object) {
    printf("AVLN(network) HFID                                   : %s\n",
           json_object_get_string(object, "avln_hfid"));
    printf("Manufacturer-set HFID                                : %s\n",
           json_object_get_string(object, "m_hfid"));
    printf("User-set HFID                                        : %s\n",
           json_object_get_string(object, "u_hfid"));
}

static bool conf_file_parse_enable_nvram(JSON_Object *object) {
    bool status = false;
    printf("Enable NVRAM                                         : ");
    int value = json_object_get_boolean(object, "use_nvram");
    if (-1 == value)
        printf("parse failed!\n");
    else {
        if (0 != value) {
            printf("true\n");
            status = true;
        } else
            printf("false\n");
    }
    return status;
}

static void conf_file_parse_store_key_change(JSON_Object *object) {
    int value;
    printf("Store Key Change                                     : ");
    value = json_object_get_boolean(object, "host_set_key_save");
    if (-1 == value)
        printf("parse failed!\n");
    else {
        if (0 != value)
            printf("true\n");
        else
            printf("false\n");
    }
}

static void conf_file_parse_psd_limit(JSON_Object *object) {
    printf("PSD Limit                                            : ");
    unsigned int afe =
        (unsigned int)json_object_get_number(object, "direct_afe_tx_idx");
    if (afe <= 15 && afe >= 0)
        printf("%d dBm/Hz\n", (-50) - (15 - afe) * 3);
    else
        printf("parse failed!\n");
}

static void conf_file_parse_spi_slave_clk(JSON_Object *object) {
    printf("SPI Slave Input Clock                                : ");
    JSON_Object *inka_eos_object = json_object_get_object(object, "eos");

    if (!inka_eos_object)
        printf("parse SPI slave input clock failed!\n");

    unsigned int spi_clock =
        (unsigned int)json_object_get_number(inka_eos_object, "spi_clock_idx");
    if (1 == spi_clock)
        printf("6 MHz\n");
    else if (2 == spi_clock)
        printf("6.25 MHz\n");
    else if (3 == spi_clock)
        printf("6.85 MHz\n");
    else if (4 == spi_clock)
        printf("7.14 MHz\n");
    else
        printf("parse SPI slave input clock failed!\n");
}

int conf_file_parse(int argc, char *argv[]) {
    do {
        if (argc < 1)
            break;

        JSON_Value *inka_value = json_parse_file(argv[0]);
        if (!inka_value)
            break;

        JSON_Object *inka_object = json_value_get_object(inka_value);
        if (!inka_object) {
            printf("Failed : file content incorrect!\n");
            return -1;
        }

        JSON_Object *inka_hpav_object =
            json_object_get_object(inka_object, "hpav");
        JSON_Object *inka_cp_object = json_object_get_object(inka_object, "cp");
        JSON_Object *inka_phy_object =
            json_object_get_object(inka_object, "phy");

        if (!inka_hpav_object || !inka_cp_object || !inka_phy_object) {
            printf("Failed : file content incorrect!\n");
            return -1;
        }

        printf("\n");
        /** version. */
        int version = 0, sub_version = 0;
        conf_file_parse_version(inka_object, &version, &sub_version);
        /** Enable NVRAM. */
        conf_file_parse_enable_nvram(inka_object);
        /** MAC address. */
        conf_file_parse_mac(inka_object);
        /** NMK. */
        conf_file_parse_nmk(inka_hpav_object);
        /** NID. */
        conf_file_parse_nid(inka_hpav_object);
        /** Role. */
        conf_file_parse_role(inka_cp_object);
        /** HFIDs. */
        conf_file_parse_hfids(inka_hpav_object);
        /** Store key change. */
        conf_file_parse_store_key_change(inka_hpav_object);
        /** PSD limit. */
        conf_file_parse_psd_limit(inka_phy_object);

        if (version == 4 && sub_version > 0) {
            /** SPI slave input clock. */
            conf_file_parse_spi_slave_clk(inka_object);
        }
        printf("\n");

        return 0;
    } while (0);
    printf("Usage : hpav_test conf_file parse filename\n");
    return EXIT_USAGE;
}

#define FCT_NAME_ENTRY(name, fct)                                              \
    { fct, #name }

struct conf_file_modify_t {
    JSON_Object *inka_obj;
    JSON_Object *inka_hpav_obj;
    JSON_Object *inka_cp_obj;
    JSON_Object *inka_phy_obj;
};
typedef struct conf_file_modify_t conf_file_modify_t;

struct fct_name_t {
    int (*fct)(conf_file_modify_t *ctx, int argc, char *argv[]);
    char name[20];
};

static int conf_file_modify_enable_nvram(conf_file_modify_t *ctx, int argc,
                                         char *argv[]) {
    if (strcmp(argv[0], "true") == 0) {
        if (JSONFailure == json_object_set_boolean(ctx->inka_obj, "use_nvram", 1))
            return -2;
    }
    else if (strcmp(argv[0], "false") == 0) {
        if (JSONFailure == json_object_set_boolean(ctx->inka_obj, "use_nvram", 0))
            return -2;
    }
    else
        return -1;
    return 0;
}

static int conf_file_modify_mac(conf_file_modify_t *ctx, int argc,
                                char *argv[]) {
    unsigned char mac[ETH_MAC_ADDRESS_SIZE];
    if (!hpav_stomac(argv[0], mac))
    {
        return -1;
    }
    unsigned long long mac_value = ((unsigned long long)mac[0] << 40) |
                                   ((unsigned long long)mac[1] << 32) |
                                   ((unsigned long long)mac[2] << 24) |
                                   ((unsigned long long)mac[3] << 16) |
                                   ((unsigned long long)mac[4] << 8) |
                                   (unsigned long long)mac[5];
    if (JSONFailure == json_object_set_number(ctx->inka_obj, "mac", (double)mac_value))
    {
        return -2;
    }
    return 0;
}

static int conf_file_modify_nmk(conf_file_modify_t *ctx, int argc,
                                char *argv[]) {
    JSON_Array *array;
    unsigned char nmk[HPAV_AES_KEY_SIZE];
    u_short count =
        sscanf(argv[0], "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:"
                        "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
               &nmk[0], &nmk[1], &nmk[2], &nmk[3], &nmk[4], &nmk[5], &nmk[6],
               &nmk[7], &nmk[8], &nmk[9], &nmk[10], &nmk[11], &nmk[12],
               &nmk[13], &nmk[14], &nmk[15]);
    if (count != HPAV_AES_KEY_SIZE)
        return -1;
    /** Update NMK. */
    array = json_object_get_array(ctx->inka_hpav_obj, "nmk");
    unsigned int i, nmk_array_val;
    for (i = 0; i < 4; i++) {
        nmk_array_val = ((unsigned int)nmk[i * 4]) |
                        ((unsigned int)nmk[i * 4 + 1] << 8) |
                        ((unsigned int)nmk[i * 4 + 2] << 16) |
                        ((unsigned int)nmk[i * 4 + 3] << 24);
        if (JSONFailure == json_array_replace_number(array, i, (double)nmk_array_val))
            return -2;
    }
    /** Clear NID. */
    if (JSONFailure == json_object_set_number(ctx->inka_hpav_obj, "nid", 0))
        return -2;
    return 0;
}

static int conf_file_modify_role(conf_file_modify_t *ctx, int argc,
                                 char *argv[]) {
    if ((strcmp(argv[0], "cco") != 0) && (strcmp(argv[0], "sta") != 0)) {
        return -1;
    }
    if (JSONFailure == json_object_set_string(ctx->inka_cp_obj, "force_role", argv[0]))
        return -2;
    return 0;
}

static int conf_file_modify_avln_hfid(conf_file_modify_t *ctx, int argc,
                                      char *argv[]) {
    if (strlen(argv[0]) > 64)
        return -1;
    if (JSONFailure == json_object_set_string(ctx->inka_hpav_obj, "avln_hfid", argv[0]))
        return -2;
    return 0;
}

static int conf_file_modify_m_hfid(conf_file_modify_t *ctx, int argc,
                                   char *argv[]) {
    if (strlen(argv[0]) > 64)
        return -1;
    if (JSONFailure == json_object_set_string(ctx->inka_hpav_obj, "m_hfid", argv[0]))
        return -2;
    return 0;
}

static int conf_file_modify_u_hfid(conf_file_modify_t *ctx, int argc,
                                   char *argv[]) {
    if (strlen(argv[0]) > 64)
        return -1;
    if (JSONFailure == json_object_set_string(ctx->inka_hpav_obj, "u_hfid", argv[0]))
        return -2;
    return 0;
}

static int conf_file_modify_store_key_change(conf_file_modify_t *ctx, int argc,
                                             char *argv[]) {
    if (strcmp(argv[0], "true") == 0) {
        if (json_object_set_boolean(ctx->inka_hpav_obj, "host_set_key_save", 1) == JSONFailure) {
            return -2;
        }
    }
    else if (strcmp(argv[0], "false") == 0) {
        if (json_object_set_boolean(ctx->inka_hpav_obj, "host_set_key_save", 0) == JSONFailure) {
            return -2;
        }
    }
    else {
        return -1;
    }
    return 0;
}

static int conf_file_modify_psd_limit(conf_file_modify_t *ctx, int argc,
                                      char *argv[]) {
    int val = atoi(argv[0]);
    if (val > -50 || val < -95)
        return -1;

    if ((-50 - val) % 3 != 0)
        return -1;

    int psd_limit = 15 - (-50 - val) / 3;

    if (JSONFailure == json_object_set_number(ctx->inka_phy_obj,
                                              "direct_afe_tx_idx",
                                              (double)psd_limit))
        return -2;

    return 0;
}

static bool Is_notched_carrier(int idx, int backoff) {
    NotchCarrierRange arrayOfNotchedArrays[11] = {
        {0, 85},      {140, 167},   {215, 225},  {283, 302},
        {410, 419},   {570, 591},   {737, 748},  {857, 882},
        {1016, 1027}, {1144, 1228}, {3529, 4095}};
    int i = 0;
    if (backoff == PSD_Notched)
        return true;

    for (i = 0; i < 6; i++) {
        if ((idx >= arrayOfNotchedArrays[i].startCarrier) &&
            (idx <= arrayOfNotchedArrays[i].endCarrier))
            return true;
    }
    return false;
}

static void removeChar(char *str, char garbage) {

    char *src, *dst;
    for (src = dst = str; *src != '\0'; src++) {
        *dst = *src;
        if (*dst != garbage)
            dst++;
    }
    *dst = '\0';
}

static int conf_file_modify_psd_cali(conf_file_modify_t *ctx, int argc,
                                     char *argv[]) {
    int lines = 0, i = 0, j = 0, m = 0, n = 0;
    FILE *fp;
    char *pch;
    char str[20];
    char carrier_range_array[4096][20];
    char compensate_value_array[4096][20];

    int first_idx, second_idx, compensate_value;

    // Parse calibration.conf line by line
    fp = fopen(argv[0], "r");
    if (fp == NULL)
    {
        return -3;
    }
    while (fgets(str, 20, fp)) {
        removeChar(str, '(');
        removeChar(str, ')');
        // Get carrier index and compensate_value
        for (j = 1, pch = strtok(str, ","); pch != NULL;
             pch = strtok(NULL, ","), j++) {
            if (j % 2 != 0)
                strcpy(carrier_range_array[lines], pch);
            else
                strcpy(compensate_value_array[lines], pch);
        }
        lines++;
    }
    fclose(fp);

    // parse psd_infile to get AmpMap
    JSON_Array *am_infile_array =
        json_object_get_array(ctx->inka_phy_obj, "am_infile");
    int am_infile_array_cnt = json_array_get_count(am_infile_array);
    int *backoff_array = malloc(sizeof(int) * am_infile_array_cnt * 8);

    for (m = 0; m < am_infile_array_cnt; m++) {
        double tmp_amp_data = 0;
        tmp_amp_data = (double)json_value_get_number(
            json_array_get_value(am_infile_array, (int)m));
        unsigned long tmp_amp_map = (unsigned long)tmp_amp_data;
        for (n = 0; n < 8; n++) {
            int shift_bits = 4 * (7 - n);
            backoff_array[m * 8 + n] = ((tmp_amp_map >> shift_bits) & 0xF);
        }
    }

    // Caculate
    for (i = 0; i < lines; i++) {
        char tmp_char[20];
        pch = strtok(carrier_range_array[i], "-");
        strcpy(tmp_char, pch);
        sscanf(tmp_char, "%d", &first_idx);

        pch = strtok(NULL, "-");
        strcpy(tmp_char, pch);
        sscanf(tmp_char, "%d", &second_idx);

        sscanf(compensate_value_array[i], "%d", &compensate_value);

        if (compensate_value % 2 == 0 &&
            (compensate_value >= -28 && compensate_value <= 28) &&
            (compensate_value != 0)) {
            for (j = first_idx; j <= second_idx; j++) {
                if (!Is_notched_carrier(j, backoff_array[j])) {
                    int tmp_PowerBackoff =
                        backoff_array[j] - compensate_value / 2;

                    if (tmp_PowerBackoff < 0)
                        backoff_array[j] = 0;
                    else if (tmp_PowerBackoff >= 0xF)
                        backoff_array[j] = 0xE;
                    else
                        backoff_array[j] = tmp_PowerBackoff;
                }
            }
        } else
            printf("compensate value=%d in %s line %d is incorrect.\n",
                   compensate_value, argv[0], i + 1);
    }
    // save psd_infile
    json_array_clear(am_infile_array);
    for (i = 0; i < am_infile_array_cnt * 8; i++) {
        unsigned long tmp_amp_map;
        tmp_amp_map |= (backoff_array[i] << ((7 - (i % 8)) * 4));
        if (i % 8 == 7) {
            if (JSONFailure == json_array_append_number(am_infile_array, tmp_amp_map))
                return -2;
            tmp_amp_map = 0;
        }
    }
    return 0;
}

static int conf_file_modify_spi_slave_clk(conf_file_modify_t *ctx, int argc,
                                          char *argv[]) {
    int version = (int)json_object_get_number(ctx->inka_obj, "version");
    int sub_version = (int)json_object_get_number(ctx->inka_obj, "sub_version");

    if (4 == version && sub_version > 0) {
        JSON_Object *eos_obj = json_object_get_object(ctx->inka_obj, "eos");
        int spi_clk_idx = atoi(argv[0]);
        if (!eos_obj || spi_clk_idx < 1 || spi_clk_idx > 4)
            return -1;

        if (JSONFailure == json_object_set_number(eos_obj, "spi_clock_idx",
                                                  (double)spi_clk_idx))
            return -2;
    } else
        printf("Failed : version mismatch!\n");

    return 0;
}

static void conf_file_modify_help_message(void) {
    printf("\nUsage : hpav_test conf_file modify filename "
           "mac|nmk|role|avln_hfid|m_hfid|u_hfid|enable_nvram|store_key_change|"
           "psd_limit|psd_cali|spi_slave_clk input\n");
    printf("mac                                                  : "
           "xx:xx:xx:xx:xx:xx\n");
    printf("nmk                                                  : "
           "xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx\n");
    printf("role                                                 : cco|sta\n");
    printf("avln_hfid                                            : string (up "
           "to 64 characters)\n");
    printf("m_hfid                                               : string (up "
           "to 64 characters)\n");
    printf("u_hfid                                               : string (up "
           "to 64 characters)\n");
    printf(
        "enable_nvram                                         : true|false\n");
    printf(
        "store_key_change                                     : true|false\n");
    printf("psd_limit                                            : "
           "-50|-53|-56|....|-95 (must be the value of (-50 - (3 x n)), min : "
           "-95, max : -50)\n");
    printf("psd_cali                                             : filename "
           "(calibration.conf)\n");
    printf("spi_slave_clk                                        : 1|2|3|4 (1 "
           ": 6MHz, 2 : 6.25MHz, 3 : 6.85MHz, 4 : 7.14MHz)\n");
    printf("\n");
}

static const struct fct_name_t conf_file_modify_fct_name_table[] = {
    FCT_NAME_ENTRY(mac, conf_file_modify_mac),
    FCT_NAME_ENTRY(enable_nvram, conf_file_modify_enable_nvram),
    FCT_NAME_ENTRY(store_key_change, conf_file_modify_store_key_change),
    FCT_NAME_ENTRY(nmk, conf_file_modify_nmk),
    FCT_NAME_ENTRY(role, conf_file_modify_role),
    FCT_NAME_ENTRY(avln_hfid, conf_file_modify_avln_hfid),
    FCT_NAME_ENTRY(m_hfid, conf_file_modify_m_hfid),
    FCT_NAME_ENTRY(u_hfid, conf_file_modify_u_hfid),
    FCT_NAME_ENTRY(psd_limit, conf_file_modify_psd_limit),
    FCT_NAME_ENTRY(psd_cali, conf_file_modify_psd_cali),
    FCT_NAME_ENTRY(spi_slave_clk, conf_file_modify_spi_slave_clk),
};

static conf_file_modify_t cfmodify;

int conf_file_modify(int argc, char *argv[]) {
    int result = -1;
    conf_file_modify_t *ctx = &cfmodify;
    do {
        if (argc < 3)
            break;
        JSON_Value *inka_value = json_parse_file(argv[0]);
        if (!inka_value)
            break;
        ctx->inka_obj = json_value_get_object(inka_value);
        if (!ctx->inka_obj) {
            printf("Failed : file incorrect!\n");
            return -1;
        }
        ctx->inka_hpav_obj = json_object_get_object(ctx->inka_obj, "hpav");
        ctx->inka_cp_obj = json_object_get_object(ctx->inka_obj, "cp");
        ctx->inka_phy_obj = json_object_get_object(ctx->inka_obj, "phy");
        if (!ctx->inka_hpav_obj || !ctx->inka_cp_obj || !ctx->inka_phy_obj) {
            printf("Failed : file incorrect!\n");
            return -1;
        }

        int nb_fct = (sizeof(conf_file_modify_fct_name_table) /
                      sizeof(struct fct_name_t)) -
                     1;
        int i = 0;
        for (i = nb_fct; i >= 0; i--)
            if (strcmp(argv[1], conf_file_modify_fct_name_table[i].name) == 0) {
                result = conf_file_modify_fct_name_table[i].fct(ctx, argc - 2,
                    &argv[2]);
                if (0 == result) {
                    /** Update modified value to file. */
                    json_serialize_to_file(inka_value, argv[0]);
                    return 0;
                }
                else if (result == -1) {
                    printf("[Error] %s is in invalid format or not a permitted value.\n", conf_file_modify_fct_name_table[i].name);
                    result = EXIT_USAGE;
                    break;
                }
                else if (result == -2) {
                    printf("[Error] error in json file operation\n");
                    break;
                }
                else if (result == -3) {
                    printf("[Error] Can not open calibrations.conf\n");
                    break;
                }
                else
                    break;
            }
    } while (0);
    /** Print help message. */
    conf_file_modify_help_message();
    return result;
}
