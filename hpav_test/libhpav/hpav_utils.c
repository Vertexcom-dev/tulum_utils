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

#include <stdio.h>

#include "hpav_api.h"
#include "hpav_mtk_api.h"

#include "hpav_utils.h"

unsigned char hpav_spid_oui[HPAV_OUI_SIZE] = {0x00, 0x13, 0xD7};
unsigned char hpav_itln_oui[HPAV_OUI_SIZE] = {0x00, 0xB0, 0x52};
unsigned char hpav_gigl_oui[HPAV_OUI_SIZE] = {0x00, 0x1F, 0x84};
unsigned char hpav_arka_oui[HPAV_OUI_SIZE] = {0x00, 0x80, 0xE1};
unsigned char hpav_stmi_oui[HPAV_OUI_SIZE] = {0x00, 0x13, 0x34};

#ifdef WIN32
// Windows specific utility functions

int hpav_get_sys_time(struct hpav_sys_time *sys_time) {
    GetSystemTime(&sys_time->win_sys_time);
    // GetSytemeTime doesn't return any error code. Always return 0 here.
    return 0;
}

int hpav_get_elapsed_time_ms(struct hpav_sys_time *p_start_sys_time,
                             struct hpav_sys_time *p_end_sys_time) {
    // This is the recommended way on Windows
    FILETIME start_file_time;
    FILETIME end_file_time;
    LARGE_INTEGER start_i64;
    LARGE_INTEGER end_i64;

    // This Win32 call can fail, but MSDN doesn't say how...
    SystemTimeToFileTime(&p_start_sys_time->win_sys_time, &start_file_time);
    SystemTimeToFileTime(&p_end_sys_time->win_sys_time, &end_file_time);

    start_i64.LowPart = start_file_time.dwLowDateTime;
    start_i64.HighPart = start_file_time.dwHighDateTime;
    end_i64.LowPart = end_file_time.dwLowDateTime;
    end_i64.HighPart = end_file_time.dwHighDateTime;
    // File time has 100ns accuracy. Divide by 10000 to get ms.
    return (int)(((__int64)end_i64.QuadPart - (__int64)start_i64.QuadPart) /
                 (__int64)10000);
}

int hpav_sleep(int amount_ms) {
    Sleep(amount_ms);
    return HPAV_OK;
}

#else
#include <unistd.h>
#include <arpa/inet.h>
// UNIX specific utility functions
int hpav_get_sys_time(struct hpav_sys_time *sys_time) {
    clock_gettime(CLOCK_MONOTONIC, &sys_time->linux_sys_time);
    return 0;
}

int hpav_get_elapsed_time_ms(struct hpav_sys_time *p_start_sys_time,
                             struct hpav_sys_time *p_end_sys_time) {
    return (p_end_sys_time->linux_sys_time.tv_sec -
            p_start_sys_time->linux_sys_time.tv_sec) *
               1000 +
           (p_end_sys_time->linux_sys_time.tv_nsec -
            p_start_sys_time->linux_sys_time.tv_nsec) /
               1000000;
}

int hpav_sleep(int amount_ms) {
    usleep(amount_ms * 1000);
    return HPAV_OK;
}

#endif

char *hpav_mactos(const unsigned char *mac_address, char *out) {
    sprintf(out, "%02x:%02x:%02x:%02x:%02x:%02x", mac_address[0],
            mac_address[1], mac_address[2], mac_address[3], mac_address[4],
            mac_address[5]);
    return out;
}

char *hpav_nidtos(const unsigned char nid[7], char *out) {
    sprintf(out, "%02x:%02x:%02x:%02x:%02x:%02x:%02x", nid[0], nid[1], nid[2],
            nid[3], nid[4], nid[5], nid[6]);
    return out;
}

char *hpav_cidtos(const unsigned char cid[2], char *out) {
    sprintf(out, "%02x:%02x", cid[0], cid[1]);
    return out;
}

char *hpav_md5sumtos(const unsigned char md5sum[HPAV_MD5SUM_SIZE], char *out) {
    sprintf(out,
            "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
            md5sum[0], md5sum[1], md5sum[2], md5sum[3], md5sum[4], md5sum[5],
            md5sum[6], md5sum[7], md5sum[8], md5sum[9], md5sum[10], md5sum[11],
            md5sum[12], md5sum[13], md5sum[14], md5sum[15]);
    return out;
}

char *hpav_aeskeytos(const unsigned char aeskey[HPAV_AES_KEY_SIZE], char *out) {
    return hpav_md5sumtos(aeskey, out);
}

unsigned short hpav_ntohs(unsigned short data) { return ntohs(data); }

unsigned short hpav_htons(unsigned short data) { return htons(data); }

unsigned int hpav_ntohl(unsigned int data) { return ntohl(data); }

unsigned int hpav_htonl(unsigned int data) { return htonl(data); }

bool hpav_stomac(const char *mac_addr, unsigned char *out) {
    // Temporary buffer to avoid buffer overrun in the output buffer
    unsigned char temp_buff[16]; // should be at least 9
    u_short count = sscanf(mac_addr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                           &temp_buff[0], &temp_buff[1], &temp_buff[2],
                           &temp_buff[3], &temp_buff[4], &temp_buff[5]);
    if (count != 6) {
        return false;
    } else {
        memcpy(out, temp_buff, 6);
    }

    return true;
}

unsigned char *hpav_stonid(const char *nid, unsigned char *out) {
    // Temporary buffer to avoid buffer overrun in the output buffer
    unsigned char temp_buff[16]; // should be at least 9
    u_short count =
        sscanf(nid, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &temp_buff[0],
               &temp_buff[1], &temp_buff[2], &temp_buff[3], &temp_buff[4],
               &temp_buff[5], &temp_buff[6]);
    if (count != 7) {
        memset(out, 0, 7);
    } else {
        memcpy(out, temp_buff, 7);
    }

    return out;
}

unsigned char *hpav_stocid(const char *nid, unsigned char *out) {
    // Temporary buffer to avoid buffer overrun in the output buffer
    unsigned char temp_buff[16];
    u_short count = sscanf(nid, "%hhx:%hhx", &temp_buff[0], &temp_buff[1]);
    if (count != 2) {
        memset(out, 0, 2);
    } else {
        memcpy(out, temp_buff, 2);
    }

    return out;
}

unsigned char *hpav_stomd5sum(const char *mac_addr, unsigned char *out) {
    // Temporary buffer to avoid buffer overrun in the output buffer
    unsigned char temp_buff[HPAV_MD5SUM_SIZE + 7];
    u_short count =
        sscanf(mac_addr, "%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%"
                         "2hhx%2hhx%2hhx%2hhx%2hhx%2hhx",
               &temp_buff[0], &temp_buff[1], &temp_buff[2], &temp_buff[3],
               &temp_buff[4], &temp_buff[5], &temp_buff[6], &temp_buff[7],
               &temp_buff[8], &temp_buff[9], &temp_buff[10], &temp_buff[11],
               &temp_buff[12], &temp_buff[13], &temp_buff[14], &temp_buff[15]);
    if (count != HPAV_MD5SUM_SIZE) {
        memset(out, 0, HPAV_MD5SUM_SIZE);
    } else {
        memcpy(out, temp_buff, HPAV_MD5SUM_SIZE);
    }

    return out;
}

int hpav_stommtype(const char *mmtype, unsigned short *result,
                   struct hpav_error **error_stack) {
    // Temporary buffer to avoid buffer overrun in the output buffer
    unsigned char temp_buff[16];
    u_short count = sscanf(mmtype, "%2hhx:%2hhx", &temp_buff[0], &temp_buff[1]);
    if (count != 2) {
        char buffer[128];
        sprintf(buffer, "Cannot read MME type from <%s>\n", mmtype);
        hpav_add_error(error_stack, hpav_error_category_input,
                       hpav_error_module_core, HPAV_ERROR_INPUT_PARSING_ERROR,
                       "sscanf failed on input in hpav_stommtype", buffer);
        return HPAV_ERROR_INPUT_PARSING_ERROR;
    } else {
        *result = temp_buff[0];
        *result = (*result) << 8;
        *result = (*result) | temp_buff[1];
        return HPAV_OK;
    }
}

char *hpav_mme_category_tos(unsigned int mme_category, char *out) {
    switch (mme_category) {
    case MME_HEADER_CATEGORY_CC:
        strcpy(out, "CC");
        break;
    case MME_HEADER_CATEGORY_CP:
        strcpy(out, "CP");
        break;
    case MME_HEADER_CATEGORY_NN:
        strcpy(out, "NN");
        break;
    case MME_HEADER_CATEGORY_CM:
        strcpy(out, "CM");
        break;
    case MME_HEADER_CATEGORY_MS:
        strcpy(out, "MS");
        break;
    case MME_HEADER_CATEGORY_VS:
        strcpy(out, "VS");
        break;
    default:
        sprintf(out, "Unknow category (%d)", mme_category);
        break;
    }
    return out;
}

// Convert a MME subtype to a string
char *hpav_mme_subtype_tos(unsigned int mme_subtype, char *out) {
    switch (mme_subtype) {
    case MME_HEADER_SUBTYPE_REQ:
        strcpy(out, "REQ");
        break;
    case MME_HEADER_SUBTYPE_CNF:
        strcpy(out, "CNF");
        break;
    case MME_HEADER_SUBTYPE_IND:
        strcpy(out, "IND");
        break;
    case MME_HEADER_SUBTYPE_RSP:
        strcpy(out, "RSP");
        break;
    default:
        sprintf(out, "Unknow subtype (%d)", mme_subtype);
        break;
    }
    return out;
}

int hpav_oui_to_origin(const unsigned char oui[HPAV_OUI_SIZE]) {
    if (memcmp(oui, hpav_spid_oui, HPAV_OUI_SIZE) == 0) {
        return HPAV_MTK_MME;
    }
    if (memcmp(oui, hpav_itln_oui, HPAV_OUI_SIZE) == 0) {
        return HPAV_INTELLON_MME;
    }
    if (memcmp(oui, hpav_gigl_oui, HPAV_OUI_SIZE) == 0) {
        return HPAV_GIGLE_MME;
    }
    if (memcmp(oui, hpav_arka_oui, HPAV_OUI_SIZE) == 0) {
        return HPAV_ARKADOS_MME;
    }
    if (memcmp(oui, hpav_stmi_oui, HPAV_OUI_SIZE) == 0) {
        return HPAV_STMICRO_MME;
    }
    return HPAV_UNKNOWN_VENDOR_MME;
}

// OUI is required for VS and MS MME
char *hpav_mmetypetos(unsigned short mme_type,
                      const unsigned char oui[HPAV_OUI_SIZE], char *out) {
    // To simplify the code, we extract first the MME subtype and append it to
    // the MME type itself
    unsigned int mme_subtype =
        ((mme_type & MME_HEADER_SUBTYPE_MASK) >> MME_HEADER_SUBTYPE_SHIFT);
    unsigned int mme_category =
        ((mme_type & MME_HEADER_CATEGORY_MASK) >> MME_HEADER_CATEGORY_SHIFT);
    unsigned int mme_main_type = mme_type & (~MME_HEADER_SUBTYPE_MASK);
    char buffer[64];
    hpav_mme_subtype_tos(mme_subtype, buffer);

    switch (mme_category) {
    case MME_HEADER_CATEGORY_CC:
        switch (mme_main_type) {
        default:
            sprintf(out, "0X%04X.%s", mme_main_type, buffer);
            break;
        }
        break;
    case MME_HEADER_CATEGORY_CP:
        switch (mme_main_type) {
        default:
            sprintf(out, "0X%04X.%s", mme_main_type, buffer);
            break;
        }
        break;
    case MME_HEADER_CATEGORY_NN:
        switch (mme_main_type) {
        default:
            sprintf(out, "0X%04X.%s", mme_main_type, buffer);
            break;
        }
        break;
    case MME_HEADER_CATEGORY_CM:
        switch (mme_main_type) {
        case (MMTYPE_CM_ENCRYPTED_PAYLOAD_IND & (~MME_HEADER_SUBTYPE_MASK)):
            sprintf(out, "CM_ENCRYPTED_PAYLOAD.%s", buffer);
            break;
        case MMTYPE_CM_SET_KEY_REQ:
            sprintf(out, "CM_SET_KEY.%s", buffer);
            break;
        case MMTYPE_CM_AMP_MAP_REQ:
            sprintf(out, "CM_AMP_MAP.%s", buffer);
            break;
        default:
            sprintf(out, "0X%04X.%s", mme_main_type, buffer);
            break;
        }
        break;
    case MME_HEADER_CATEGORY_MS:
    case MME_HEADER_CATEGORY_VS:
        // Here we use the OUI to lookup the MME string
        switch (hpav_oui_to_origin(oui)) {
        case HPAV_MTK_MME:
            switch (mme_main_type) {
            case MMTYPE_MTK_VS_GET_VERSION_REQ:
                sprintf(out, "VS_GET_VERSION.%s", buffer);
                break;
            case MMTYPE_MTK_VS_RESET_REQ:
                sprintf(out, "VS_RESET.%s", buffer);
                break;
            case MMTYPE_MTK_VS_GET_NVRAM_REQ:
                sprintf(out, "VS_GET_NVRAM.%s", buffer);
                break;
            case MMTYPE_MTK_VS_GET_TONEMASK_REQ:
                sprintf(out, "VS_GET_TONEMASK.%s", buffer);
                break;
            case MMTYPE_MTK_VS_GET_ETH_PHY_REQ:
                sprintf(out, "VS_GET_ETH_PHY.%s", buffer);
                break;
            case MMTYPE_MTK_VS_ETH_STATS_REQ:
                sprintf(out, "VS_ETH_STATS.%s", buffer);
                break;
            case MMTYPE_MTK_VS_GET_STATUS_REQ:
                sprintf(out, "VS_GET_STATUS.%s", buffer);
                break;
            case MMTYPE_MTK_VS_GET_TONEMAP_REQ:
                sprintf(out, "VS_GET_TONEMAP.%s", buffer);
                break;
            case MMTYPE_MTK_VS_SET_CAPTURE_STATE_REQ:
                sprintf(out, "VS_SET_CAPTURE_STATE.%s", buffer);
                break;
            case MMTYPE_MTK_VS_GET_SNR_REQ:
                sprintf(out, "VS_GET_SNR.%s", buffer);
                break;
            case MMTYPE_MTK_VS_GET_LINK_STATS_REQ:
                sprintf(out, "VS_GET_LINK_STATS.%s", buffer);
                break;
            case MMTYPE_MTK_VS_SET_NVRAM_REQ:
                sprintf(out, "VS_SET_NVRAM.%s", buffer);
                break;
            case MMTYPE_MTK_VS_PWM_GENERATION_REQ:
                sprintf(out, "VS_PWM_GENERATION.%s", buffer);
                break;
            default:
                sprintf(out, "0X%04X.%s", mme_main_type, buffer);
                break;
            }
            break;
        default:
            sprintf(out, "0X%04X.%s", mme_main_type, buffer);
            break;
        }
        break;
    default:
        sprintf(out, "0X%04X.%s", mme_main_type, buffer);
        break;
    }
    return out;
}

// Given a MME header, find out if the MME is a standard one, a VS or MS, and
unsigned int hpav_guess_mme_category(struct hpav_mme_frame *mme_frame,
                                     unsigned int *mme_category,
                                     unsigned char oui[HPAV_OUI_SIZE],
                                     unsigned int *mme_header_size) {
    *mme_category = (mme_frame->header.mmtype & 0xE000) >> 13;
    switch (*mme_category) {
    case MME_HEADER_CATEGORY_CC:
    case MME_HEADER_CATEGORY_CP:
    case MME_HEADER_CATEGORY_NN:
    case MME_HEADER_CATEGORY_CM:
        // Standard MME
        *mme_header_size = sizeof(struct hpav_mme_header);
        oui[0] = 0;
        oui[1] = 0;
        oui[2] = 0;
        return HPAV_STANDARD_MME;
        break;
    case MME_HEADER_CATEGORY_MS:
    case MME_HEADER_CATEGORY_VS: {
        // MS or VS MME
        // Special processing to extract vendor OUI
        struct hpav_mtk_mme_frame *mtk_mme =
            (struct hpav_mtk_mme_frame *)mme_frame;
        if (memcmp(mtk_mme->header.oui, hpav_spid_oui, HPAV_OUI_SIZE) == 0) {
            *mme_header_size = sizeof(struct hpav_mtk_mme_header);
            memcpy(oui, hpav_spid_oui, HPAV_OUI_SIZE);
            return HPAV_MTK_MME;
        }
        // In theory, we could guess the OUI by using spidcom header (which
        // follows the spec)
        // but given the situation with Intellon, there is no guaranty this
        // would be a reliable guess.
    }
    // fallback to default label
    default:
        oui[0] = 0;
        oui[1] = 0;
        oui[2] = 0;
        *mme_header_size = 0;
        return HPAV_UNKNOWN_VENDOR_MME;
        break;
    }
}

void hpav_compute_elapsed(const struct timeval *start,
                          const struct timeval *end, struct timeval *elapsed) {
    // No check for weird cases
    elapsed->tv_sec = end->tv_sec - start->tv_sec;
    if (end->tv_usec >= start->tv_usec) {
        // Standard case
        elapsed->tv_usec = end->tv_usec - start->tv_usec;
    } else {
        elapsed->tv_usec = end->tv_usec + (1000000 - start->tv_usec);
        if (elapsed->tv_usec > 1000000) {
            elapsed->tv_usec -= 1000000;
        } else {
            elapsed->tv_sec--;
        }
    }
}

#define BYTES_PER_LINE 16
int hpav_dump_bitfield(const unsigned char *bitfield, int num_bytes) {
    int num_bytes_left = num_bytes;
    while (num_bytes_left > 0) {
        unsigned int byte_index;
        unsigned int line_bytes =
            ((num_bytes_left >= BYTES_PER_LINE) ? BYTES_PER_LINE
                                                : num_bytes_left);
        // Dump 16 bytes by 16 bytes
        for (byte_index = 0; byte_index < line_bytes; ++byte_index) {
            printf("%02x ", bitfield[num_bytes - num_bytes_left + byte_index]);
        }
        printf("\n");
        num_bytes_left -= BYTES_PER_LINE;
    }

    return 0;
}

int hpav_dump_tonemap(const unsigned char *bitfield, int num_bits,
                      int rle_enc) {
#define IS_MODULATION_FIELD(x) (((x) >= 0) && ((x) <= 0x8))
#define IS_NIBBLE_FIELD(x) (((x) >= 9) && ((x) <= 0xF))
#define GET_RLE_LEN(x, y) ((((x)-8) * 7) + (((y)-9) + 3))
#define GET_HIGH_NIBBLE(x) (((x)&0xF0) >> 4)
#define GET_LOW_NIBBLE(x) ((x)&0x0F)
    /* Modulation list means decoded tonemap */
    unsigned char modulation_list[MTK_POSSIBLE_CARRIERS_MAX + 1];
    char modulation = -1;
    int rle = -1;
    unsigned char tmp[2];
    unsigned int i = 0, j = 0, k = 0, m = 0;

    if (rle_enc == 0xFF) {
        for (i = 0; (int)i < num_bits / 8; i++) {
            tmp[1] = GET_HIGH_NIBBLE(bitfield[i]);
            tmp[0] = GET_LOW_NIBBLE(bitfield[i]);
            for (j = 0; j < 2; j++) {
                if (IS_MODULATION_FIELD(tmp[j])) {
                    if (modulation != -1) {
                        if (rle == -1) {
                            modulation_list[m] = modulation;
                            m++;
                            modulation = -1;
                        } else {
                            rle = GET_RLE_LEN(8, rle);
                            for (k = 0; (int)k < rle; k++, m++)
                                modulation_list[m] = modulation;
                            rle = -1;
                            modulation = -1;
                        }
                    }
                    modulation = tmp[j];
                } else if (IS_NIBBLE_FIELD(tmp[j])) {
                    if (rle == -1)
                        rle = tmp[j];
                    else {
                        rle = GET_RLE_LEN(tmp[j], rle);
                        for (k = 0; (int)k < rle; k++, m++)
                            modulation_list[m] = modulation;
                        rle = -1;
                        modulation = -1;
                    }
                }
            }
        }

        if (num_bits % 8) {
            tmp[0] = GET_LOW_NIBBLE(bitfield[i]);

            if (IS_MODULATION_FIELD(tmp[0])) {
                modulation_list[m] = tmp[0];
                m++;
            } else if (IS_NIBBLE_FIELD(tmp[0])) {
                if (rle == -1)
                    rle = GET_RLE_LEN(8, tmp[0]);
                else
                    rle = GET_RLE_LEN(tmp[0], rle);
                for (k = 0; (int)k < rle; k++, m++)
                    modulation_list[m] = modulation;
            }
        }

        for (i = 0; i < m / 2; ++i) {
            unsigned char swap =
                modulation_list[i * 2] << 4 | modulation_list[i * 2 + 1];

            if (i % 16 == 0)
                printf("0x%04X: ", i);
            printf("%02x ", swap);
            if ((i + 1) % 16 == 0)
                printf("\n");
        }

        if (m % 2) {
            if (i % 16 == 0)
                printf("0x%04X: ", i);
            printf("%x ", modulation_list[m - 1]);
        }
    } else {
        int num_bytes_left = num_bits / 8;
        i = 0;
        while (num_bytes_left > 0) {
            unsigned int byte_index;
            unsigned int line_bytes =
                ((num_bytes_left >= BYTES_PER_LINE) ? BYTES_PER_LINE
                                                    : num_bytes_left);
            printf("0x%04X: ", i);
            i += 16;
            // Dump 16 bytes by 16 bytes
            for (byte_index = 0; byte_index < line_bytes; ++byte_index) {
                unsigned char swap =
                    bitfield[num_bits / 8 - num_bytes_left + byte_index] << 4 |
                    bitfield[num_bits / 8 - num_bytes_left + byte_index] >> 4;
                printf("%02x ", swap);
            }
            printf("\n");
            num_bytes_left -= BYTES_PER_LINE;
            if ((num_bytes_left == 0) && (num_bits % 8)) {
                if (line_bytes == BYTES_PER_LINE)
                    printf("0x%04X: ", i);
                printf("%x ", bitfield[num_bits / 8]);
            }
        }
    }

    return 0;
}

int hpav_file_to_binary_data(const char *filename, unsigned char **result_data,
                             unsigned int *data_size,
                             struct hpav_error **error_stack) {
    FILE *fd;

    // Init
    *data_size = 0;
    *result_data = NULL;

    // Open file
    fd = fopen(filename, "rb");
    if (fd == NULL) {
        char buffer[128];
        sprintf(buffer, "Cannot open file <%s>\n", filename);
        hpav_add_error(error_stack, hpav_error_category_input,
                       hpav_error_module_core, HPAV_ERROR_CANNOT_OPEN_FILE,
                       "fopen failed in hpav_file_to_binary_data", buffer);
        return HPAV_ERROR_CANNOT_OPEN_FILE;
    }

    // Get size
    fseek(fd, 0, SEEK_END);
    *data_size = ftell(fd);
    fseek(fd, 0, SEEK_SET);

    // Allocate buffer
    *result_data = (unsigned char *)malloc(*data_size);
    // Read file data
    fread(*result_data, 1, *data_size, fd);
    // Close file
    fclose(fd);
    return HPAV_OK;
}

const char *hpav_get_range_value_str(unsigned int value,
                                     const struct range_string *value_str,
                                     int size) {
    int i = 0;

    if (NULL == value_str) {
        return "Unknown";
    }

    for (i = 0; i < size; i++) {
        if ((value >= value_str[i].value_min) &&
            (value <= value_str[i].value_max)) {
            return value_str[i].strptr;
        }
    }

    return "Unknown";
}

const char *hpav_get_value_str(unsigned int value,
                               const struct value_string *value_str, int size) {
    int i = 0;

    if (NULL == value_str) {
        return "Unknown";
    }

    for (i = 0; i < size; i++) {
        if (value_str[i].value == value) {
            return value_str[i].strptr;
        }
    }

    return "Unknown";
}
