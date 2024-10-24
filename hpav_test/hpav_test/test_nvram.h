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
#if defined(_MSC_VER)
#define __packed
#define __packed_end
#pragma pack(push, hpav, 1)
#else
#define __packed
#define __packed_end __attribute__((packed))
#endif

int test_nvram_read(int argc, char *argv[]);
int test_nvram_write(int argc, char *argv[]);
int test_nvram_parse(int argc, char *argv[]);
int test_nvram_modify(int argc, char *argv[]);

typedef __packed struct {
    char magic[8]; /* Magic number "MSTARNV\0" */
    char reserved[16];
    char version[4]; /* NVRAM version */
    char reserved2[4];
    char product_name[64];   /* Product short name in string format */
    char product_partnb[64]; /* Product part number in string format */
    char product_desc[128];  /* Product long description in string format*/
    char serial_number[64];  /* Product serial number in string format */
    char reserved3[256];
    char vendor_info[64];      /* Vendor info */
    char manufactory_info[64]; /* Name of the product manufacturer */
    char oem_info[64];         /* OEM information */
    char reserved4[128];
    unsigned char mac[6]; /* MAC address */
    char reserved5[2];
    char device_password[32]; /* HomePlugAV device unique password (DPW) */
} __packed_end nvram_t;

#if defined(_MSC_VER)
#pragma pack(pop, hpav)
#endif