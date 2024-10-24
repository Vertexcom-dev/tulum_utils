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
#define _CRT_SECURE_NO_WARNINGS 1

#include "hpav_error.h"
#include "hpav_api.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/// Free a list of errors (i.e the \c error_stack).
///
/// Memory used by the list of hpav_error is freed and \c error_stack
/// set to \c NULL
///
/// \param error_stack[in, out] Pointer to \c error_stack.
///
/// \retval status Returns zero on no error and non-zero on error
///
int hpav_free_error_stack(struct hpav_error **error_stack) {
    struct hpav_error *current_error = *error_stack;
    while (current_error != NULL) {
        struct hpav_error *next_error = current_error->next;
        free(current_error->message);
        free(current_error->details);
        free(current_error);
        current_error = next_error;
    }
    // Make it NULL so it can be reused without worrying about reinit
    *error_stack = NULL;
    return 0;
}

/// Add a new error to the \c error_stack.
///
/// Creates a new hpav_error from the parameters provided and appends the
/// previous \c error_stack
/// to the newly created hpav_error. \c error_stack is updated to point to the
/// new stack.
//  \c *error_stack must be initialized to \c NULL by the
/// highest level caller (the one who will report the errors to the user).
///
/// \param error_stack[in, out] Pointer to \c error_stack.
/// \param error_category[in] Category of error.
/// \param error_module[in] Module issuing the error.
/// \param error_code[in] Module specific error code.
/// \param message[in] Human readable message.
/// \param details[in] Details for the errors.
///
/// \retval status Returns zero on no error and non-zero on error
///
/// \warning This is not thread safe "as is" : \c error_stack must not be shared
/// between different
/// threads without special measures : calls to this function on the same \c
/// error_stack must be
/// synchronized with a lock or critical section.
///
int hpav_add_error(struct hpav_error **error_stack,
                   enum hpav_error_category error_category,
                   enum hpav_error_module error_module, int error_code,
                   const char *message, const char *details) {
    struct hpav_error *new_error =
        (struct hpav_error *)malloc(sizeof(struct hpav_error));
    memset(new_error, 0, sizeof(struct hpav_error));

    new_error->next =
        *error_stack;         // These two lines are the thread unsafe ones
    *error_stack = new_error; //

    new_error->category = error_category;
    new_error->module = error_module;
    new_error->error_code = error_code;
    if (message != NULL) {
        new_error->message = (char *)malloc(strlen(message) + 1);
        strcpy(new_error->message, message);
    }
    if (details != NULL) {
        new_error->details = (char *)malloc(strlen(details) + 1);
        strcpy(new_error->details, details);
    }

    return 0;
}

/// Convert a hpav_error_category to a string.
///
/// \param error_category[in, out] Category of error.
/// \param buffer[in] User supplied char buffer to hold string
/// \retval buffer Returns the \c buffer with the category as a string.
///
char *hpav_error_category_to_string(enum hpav_error_category error_category,
                                    char *buffer) {
    switch (error_category) {
    case hpav_error_category_unknown:
        strcpy(buffer, "Unknown");
        break;
    case hpav_error_category_network:
        strcpy(buffer, "Network");
        break;
    case hpav_error_category_internal:
        strcpy(buffer, "Internal");
        break;
    case hpav_error_category_protocol:
        strcpy(buffer, "Protocol");
        break;
    case hpav_error_category_input:
        strcpy(buffer, "Input");
        break;
    default:
        sprintf(buffer, "Unrecognized (%d)", error_category);
        break;
    }
    return buffer;
}

/// Convert a hpav_error_module to a string.
///
/// \param error_module[in, out] Error reporting error.
/// \param buffer[in] User supplied char buffer to hold string
/// \retval buffer Returns the \c buffer with the module as a string.
///
char *hpav_error_module_to_string(enum hpav_error_module error_module,
                                  char *buffer) {
    switch (error_module) {
    case hpav_error_module_unknown:
        strcpy(buffer, "Unknown");
        break;
    case hpav_error_module_core:
        strcpy(buffer, "CORE");
        break;
    case hpav_error_module_api:
        strcpy(buffer, "API");
        break;
    case hpav_error_module_cli:
        strcpy(buffer, "CLI");
        break;
    default:
        sprintf(buffer, "Unrecognized (%d)", error_module);
        break;
    }
    return buffer;
}

/// Outputs \c error_stack to sysout.
///
/// \param error_stack[in] Stack of hpav_error to print
/// \retval status Returns zero on no error and non-zero on error
///
int hpav_dump_error_stack(struct hpav_error *error_stack) {
    if (error_stack != NULL) {
        while (error_stack != NULL) {
            char buffer[128];
            printf("Error category : %s\n", hpav_error_category_to_string(
                                                error_stack->category, buffer));
            printf("Module         : %s\n",
                   hpav_error_module_to_string(error_stack->module, buffer));
            printf("Code           : 0x%08X\n", error_stack->error_code);
            printf("Message        : %s\n", error_stack->message);
            printf("Details        : %s\n", error_stack->details);
            error_stack = error_stack->next;
        }
    } else {
        printf("Empty error stack.\n");
    }
    return HPAV_OK;
}

/// Append two error stacks.
///
/// Appends \c error_stack to \c second_error_stack.
/// \c *error_stack is updated to point to the new stack.
///
/// \param error_stack[in, out] Pointer to \c error_stack.
/// \param second_error_stack[in] Point to new \c error_stack.
///
/// \retval status Returns zero on no error and non-zero on error
///
/// \warning // This is thread unsafe. Don't call it from different threads on
/// the same error_stack.
// \c error_stack must not be shared between different
/// threads without special measures : calls to this function on the same \c
/// error_stack must be
/// synchronized with a lock or critical section.
///
int hpav_append_error_stack(struct hpav_error **error_stack,
                            struct hpav_error *second_error_stack) {
    // Find last error in the second stack
    if (second_error_stack != NULL) {
        struct hpav_error *current_error = second_error_stack;
        while (current_error->next != NULL) {
            current_error = current_error->next;
        }
        current_error->next = *error_stack; // Thread unsafe part
        *error_stack = second_error_stack;
    }

    return HPAV_OK;
}
