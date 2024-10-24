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
#ifndef __HPAV_UTILS_H__
#define __HPAV_UTILS_H__

// home plug AV 1.0 C API

// Utility and portability functions

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32)
// Windows specific

#include <windows.h>

struct hpav_sys_time {
    // Windows system time data structure
    SYSTEMTIME win_sys_time;
};

#else
// UNIX specific data structures

#include <time.h>
struct hpav_sys_time {
    // Windows system time data structure
    struct timespec linux_sys_time;
};

#endif
#include "stdbool.h"

#include "hpav_error.h"

// Get the current systeme time
int hpav_get_sys_time(struct hpav_sys_time *sys_time);

// Compute time difference in ms
int hpav_get_elapsed_time_ms(struct hpav_sys_time *start_sys_time,
                             struct hpav_sys_time *end_sys_time);

// Sleep for a given amount of ms
int hpav_sleep(int amount_ms);

// Convert a mac address in readable string
char *hpav_mactos(const unsigned char *mac_address, char *out);

// Convert a NID to a readable string
char *hpav_nidtos(const unsigned char nid[7], char *out);

// Convert a cid to a readable string
char *hpav_cidtos(const unsigned char nid[2], char *out);

// Convert a MD5 sum to a readable string
char *hpav_md5sumtos(const unsigned char md5sum[HPAV_MD5SUM_SIZE], char *out);
// Convert an AES key to a readable string
char *hpav_aeskeytos(const unsigned char aeskey[HPAV_AES_KEY_SIZE], char *out);

/** 
 * Convert a well formed mac address to array
 * If argument "max_addr" is not in the expected format,
 * it shall return false.
 */
bool hpav_stomac(const char *mac_addr, unsigned char *out);

// Convert a well formed NID to array
unsigned char *hpav_stonid(const char *nid, unsigned char *out);

// Convert a well formed CID to array
unsigned char *hpav_stocid(const char *nid, unsigned char *out);

// Convert a well formed MD5 sum to array
unsigned char *hpav_stomd5sum(const char *md5sum, unsigned char *out);

// Convert a well formed MME type to an unsigned short
int hpav_stommtype(const char *mmtype, unsigned short *result,
                   struct hpav_error **error_stack);

// Convert a OUI to a MME origin
int hpav_oui_to_origin(const unsigned char oui[HPAV_OUI_SIZE]);

// Convert a MME category to string
char *hpav_mme_category_tos(unsigned int mme_category, char *out);

// Convert a MME subtype to a string
char *hpav_mme_subtype_tos(unsigned int mme_subtype, char *out);

// Convert a MME Type to a readable string
char *hpav_mmetypetos(unsigned short mme_type,
                      const unsigned char oui[HPAV_OUI_SIZE], char *out);

// Given a MME header, find out if the MME is a standard one, a VS or MS, and
// the vendor (Spidcom or Intellon)
unsigned int hpav_guess_mme_category(struct hpav_mme_frame *mme_frame,
                                     unsigned int *mme_category,
                                     unsigned char oui[HPAV_OUI_SIZE],
                                     unsigned int *mme_header_size);

void hpav_compute_elapsed(const struct timeval *start,
                          const struct timeval *end, struct timeval *elapsed);

int hpav_dump_bitfield(const unsigned char *bitfield, int num_bytes);

int hpav_dump_tonemap(const unsigned char *bitfield, int num_bits, int rle);

// File to binary data in memory
int hpav_file_to_binary_data(const char *filename, unsigned char **result_data,
                             unsigned int *data_size,
                             struct hpav_error **error_stack);

// Network/Host byte ordering correction
unsigned short hpav_ntohs(unsigned short data);
unsigned short hpav_htons(unsigned short data);
unsigned int hpav_ntohl(unsigned int data);
unsigned int hpav_htonl(unsigned int data);

struct value_string {
    unsigned int value;
    const char *strptr;
};

struct range_string {
    unsigned int value_min;
    unsigned int value_max;
    const char *strptr;
};

const char *hpav_get_range_value_str(unsigned int value,
                                     const struct range_string *value_str,
                                     int size);

const char *hpav_get_value_str(unsigned int value,
                               const struct value_string *value_str, int size);

#ifdef __cplusplus
}
#endif

#endif // __HPAV_UTILS_H__
