/*
 * MIT License
 *
 * Copyright (c) 2025 Vertexcom
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
#ifndef EXITCODES_H
#define EXITCODES_H

#include <stdlib.h>

/*
 * Note about exit code:
 * - on success, return 0 (EXIT_SUCCCESS)
 * - on error, return 1 (EXIT_FAILURE, general error, catch all case)
 * - when usage is printed, e.g. on wrong command/wrong syntax, return 2 (EXIT_USAGE)
 * - commands which interact with a station and no station responded, return 3 (EXIT_NO_RESPONSE)
 */
#define EXIT_USAGE 2
#define EXIT_NO_RESPONSE 3

#endif // EXITCODES_H
