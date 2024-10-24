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
#ifndef __HPAV_MTK_FIELD_H__
#define __HPAV_MTK_FIELD_H__

// Define Mstar MME fields enum value and descriptions

#ifdef __cplusplus
extern "C" {
#endif

#include "hpav_api.h"
#include "hpav_utils.h"

// Define struct include the enum value and it's description

// MME CNF Status define
enum mtk_vs_result { MTK_VS_SUCCESS, MTK_VS_FAILURE };

static const struct value_string mtkvs_result_vals[] = {
    {MTK_VS_SUCCESS, "Success"}, {MTK_VS_FAILURE, "Failure"},
};

#ifdef __cplusplus
}
#endif

#endif // __HPAV_MTK_FIELD_H__
