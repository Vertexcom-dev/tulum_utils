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
#include <stdbool.h>

#include "hpav_error.h"

// Get the current systeme time
int hpav_get_sys_time(struct hpav_sys_time *sys_time);

// Compute time difference in ms
int hpav_get_elapsed_time_ms(struct hpav_sys_time *start_sys_time,
                             struct hpav_sys_time *end_sys_time);

// Convert a mac address in readable string
char *hpav_mactos(const unsigned char *mac_address, char *out);

// Convert a NID to a readable string
char *hpav_nidtos(const unsigned char nid[7], char *out);

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

// Convert a well formed MD5 sum to array
unsigned char *hpav_stomd5sum(const char *md5sum, unsigned char *out);

int hpav_dump_bitfield(const unsigned char *bitfield, int num_bytes);

int hpav_dump_tonemap(const unsigned char *bitfield, int num_bits, int rle);

struct value_string {
    unsigned int value;
    const char *strptr;
};

#ifdef __cplusplus
}
#endif

#endif // __HPAV_UTILS_H__
