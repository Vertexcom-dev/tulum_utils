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
#ifndef __HPAV_ERROR_H__
#define __HPAV_ERROR_H__

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \addtogroup hpav_error hpav_error module
 *  @{
 *
 */

// Main structure to store errors reportable to the user
enum hpav_error_category {
    hpav_error_category_unknown = -1,
    hpav_error_category_network = 0,
    hpav_error_category_internal = 1,
    hpav_error_category_protocol = 2,
    hpav_error_category_input = 3
};

enum hpav_error_module {
    hpav_error_module_unknown = -1,
    hpav_error_module_core = 0, // libhpav/*.*
    hpav_error_module_api = 1,  // libhpav_user/hpav_user*.*
    hpav_error_module_cli = 2,  // libhpav_user/cli*.*
    hpav_error_module_itln = 3, // libhpav_intellon/*.*
    hpav_error_module_spid = 4  // libhpav_spidcom /*.*
};

/// Error stack. Linked list of hpav_error.
struct hpav_error {
    enum hpav_error_category category; ///< Error category
    enum hpav_error_module module;     ///< Module issuing the error
    int error_code;                    ///< Module specific error code
    char *message;                     ///< Human readable message
    char *details;                     ///< Details for the errors

    struct hpav_error *next; ///< Chain to next hpav_error in the list. Null if
                             /// no more errors in stack.
};

int hpav_add_error(struct hpav_error **error_stack,
                   enum hpav_error_category error_category,
                   enum hpav_error_module error_module, int error_code,
                   const char *message, const char *details);

int hpav_append_error_stack(struct hpav_error **error_stack,
                            struct hpav_error *second_error_stack);

int hpav_free_error_stack(struct hpav_error **error_stack);

int hpav_dump_error_stack(struct hpav_error *error_stack);

// Helper functions to translate codes to readable strings
char *hpav_error_category_to_string(enum hpav_error_category error_category,
                                    char *buffer);
char *hpav_error_module_to_string(enum hpav_error_module error_module,
                                  char *buffer);

/*! @} */

#ifdef __cplusplus
}
#endif

#endif
