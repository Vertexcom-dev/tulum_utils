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
// Security related functions
// Algorithms implementation comes from OpenSSL

#include "openssl/sha.h"

#include "hpav_api.h"

#define HPAV_PBKDF1_SALT_SIZE 8
#define HPAV_PBKDF1_ITERATION_COUNT 1000

// Implementation of PBKDF1 with SHA256 as underlying hash function
// Password doesn't need to be a null terminated string at this level of the API
int hpav_pbkdf1_sha256(const char *password, unsigned int password_size,
                       const unsigned char *salt, unsigned int salt_size,
                       unsigned int iteration_count, unsigned char *result,
                       unsigned int result_size) {
    // Iterate (minimum of 1)
    unsigned char digest[SHA256_DIGEST_LENGTH];
    unsigned int iteration_index;
    SHA256_CTX sha_ctx;
    SHA256_Init(&sha_ctx);
    SHA256_Update(&sha_ctx, password, password_size);
    SHA256_Update(&sha_ctx, salt, salt_size);
    SHA256_Final(digest, &sha_ctx);
    for (iteration_index = 1; iteration_index < iteration_count;
         ++iteration_index) {
        SHA256_Init(&sha_ctx);
        SHA256_Update(&sha_ctx, digest, SHA256_DIGEST_LENGTH);
        SHA256_Final(digest, &sha_ctx);
    }
    if (result_size > SHA256_DIGEST_LENGTH) {
        // Not very interesting case for the caller
        memcpy(result, digest, SHA256_DIGEST_LENGTH);
    } else {
        memcpy(result, digest, result_size);
    }
    return 0;
}

int hpav_generate_key(const char *password,
                      unsigned char salt[HPAV_PBKDF1_SALT_SIZE],
                      unsigned char result[HPAV_AES_KEY_SIZE]) {
    // Iteration count for HPAV PBKDF1 is 1000
    unsigned int iteration_count = HPAV_PBKDF1_ITERATION_COUNT;
    return hpav_pbkdf1_sha256(password, strlen(password), salt,
                              HPAV_PBKDF1_SALT_SIZE, iteration_count, result,
                              HPAV_AES_KEY_SIZE);
}

int hpav_generate_nmk(const char *password,
                      unsigned char result[HPAV_AES_KEY_SIZE]) {
    // Set salt value for NMK (?.10.7.1 in HPAV 1.1 spec)
    unsigned char salt[HPAV_PBKDF1_SALT_SIZE] = {0x08, 0x85, 0x6D, 0xAF,
                                                 0x7C, 0xF5, 0x81, 0x86};
    return hpav_generate_key(password, salt, result);
}

int hpav_generate_dak(const char *password,
                      unsigned char result[HPAV_AES_KEY_SIZE]) {
    // Set salt value for DAK (?.10.7.1 in HPAV 1.1 spec)
    unsigned char salt[HPAV_PBKDF1_SALT_SIZE] = {0x08, 0x85, 0x6D, 0xAF,
                                                 0x7C, 0xF5, 0x81, 0x85};
    return hpav_generate_key(password, salt, result);
}

int hpav_generate_nid(const unsigned char nmk[HPAV_AES_KEY_SIZE],
                      unsigned char security_level, unsigned char *result) {
    // No salt and iteration count 5 per HPAV spec
    int generation_result = hpav_pbkdf1_sha256(nmk, HPAV_AES_KEY_SIZE, NULL, 0,
                                               5, result, HPAV_NID_SIZE);

    if (generation_result == 0) {
        // Put security level (see ?.4.3.1 in the HPAV spec) :
        // shift the four MSbits to the right by four and put the security level
        // in bits 4 and 5, and zero bits 6 and 7
        result[HPAV_NID_SIZE - 1] =
            (result[HPAV_NID_SIZE - 1] >> 4) | ((security_level & 0x3) << 4);
    }

    return generation_result;
}
