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
// Utility functions for all tests
#define _CRT_SECURE_NO_WARNINGS 1
#include "hpav_api.h"
#include "hpav_utils.h"
#include "util.h"

// Dump interfaces (Interface numbering starts at 0 for the test program)
int dump_interfaces(struct hpav_if *interfaces) {
    struct hpav_if *current_interface = interfaces;
    unsigned int interface_num = 0;
    while (current_interface != NULL) {
        char buffer[64];
        printf("Interface %u : %s", interface_num, current_interface->name);
        if (current_interface->description != NULL) {
            printf(" (%s)", current_interface->description);
        }
        printf(" (MAC : %s)", hpav_mactos(current_interface->mac_addr, buffer));
        printf("\n");
        current_interface = current_interface->next;
        interface_num++;
    }
    return 0;
}

// Input data as an hexadecimal string
int string_to_binary_data(const char *input, unsigned char **result_data,
                          unsigned int *data_size) {
    unsigned int input_index;
    *data_size = strlen(input) / 2;
    *result_data = (unsigned char *)malloc(
        *data_size + 4); // Add 4 to prevent buffer overrun from sscanf (which
                         // writes 4 bytes when using %2x)
    for (input_index = 0; input_index < *data_size; ++input_index) {
        sscanf(&input[input_index * 2], "%2hhx", &(*result_data)[input_index]);
    }
    return 0;
}
