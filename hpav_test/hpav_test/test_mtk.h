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
#include "hpav_api.h"

// Declaration for Intellon test functions
typedef unsigned int u_int32_t;
void test_mme_mtk_printf_silence(void);
int test_mme_mtk_vs_get_version_req(hpav_chan_t *channel, int argc,
                                    char *argv[]);
int test_mme_mtk_vs_reset_req(hpav_chan_t *channel, int argc,
                              char *argv[]);
int test_mme_mtk_vs_reset_ind(hpav_chan_t *channel, int argc,
                              char *argv[]);
int test_mme_mtk_vs_get_tonemask_req(hpav_chan_t *channel, int argc,
                                     char *argv[]);
int test_mme_mtk_vs_get_eth_phy_req(hpav_chan_t *channel, int argc,
                                    char *argv[]);
int test_mme_mtk_vs_eth_stats_req(hpav_chan_t *channel, int argc,
                                  char *argv[]);
int test_mme_mtk_vs_get_status_req(hpav_chan_t *channel, int argc,
                                   char *argv[]);
int test_mme_mtk_vs_get_tonemap_req(hpav_chan_t *channel, int argc,
                                    char *argv[]);
int test_mme_mtk_vs_set_capture_state_req(hpav_chan_t *channel, int argc,
                                          char *argv[]);
int test_mme_mtk_vs_get_snr_req(hpav_chan_t *channel, int argc,
                                char *argv[]);
int test_mme_mtk_vs_spi_stats_req(hpav_chan_t *channel, int argc,
                                  char *argv[]);
int test_mme_mtk_vs_get_link_stats_req(hpav_chan_t *channel, int argc,
                                       char *argv[]);
int test_mme_mtk_vs_get_nw_info_req(hpav_chan_t *channel, int argc,
                                    char *argv[]);
int test_mme_mtk_vs_set_nvram_req(hpav_chan_t *channel, int argc,
                                  char *argv[]);
int test_mme_mtk_vs_get_nvram_req(hpav_chan_t *channel, int argc,
                                  char *argv[]);
int test_mme_mtk_vs_pwm_generation_req(hpav_chan_t *channel, int argc,
                                       char *argv[]);
int test_mme_mtk_vs_file_access_req(hpav_chan_t *channel, int argc,
                                    char *argv[]);
#define MTK_VS_FILE_ACCESS_REQ_PARAMETER_FAIL -1
#define MTK_VS_FILE_ACCESS_REQ_FAIL -2
int test_mme_mtk_vs_get_pwm_stats_req(hpav_chan_t *channel, int argc,
                                      char *argv[]);
#define MTK_VS_GET_PWM_STATS_REQ_PARAMETER_FAIL -1
#define MTK_VS_GET_PWM_STATS_REQ_FAIL -2
int test_mme_mtk_vs_get_pwm_conf_req(hpav_chan_t *channel, int argc,
                                     char *argv[]);
#define MTK_VS_GET_PWM_CONF_REQ_PARAMETER_FAIL -1
#define MTK_VS_GET_PWM_CONF_REQ_FAIL -2
int test_mme_mtk_vs_set_pwm_conf_req(hpav_chan_t *channel, int argc,
                                     char *argv[]);
#define MTK_VS_SET_PWM_CONF_REQ_PARAMETER_FAIL -1
#define MTK_VS_SET_PWM_CONF_REQ_FAIL -2
int test_mme_mtk_vs_set_tx_cali_req(hpav_chan_t *channel, int argc,
                                    char *argv[]);
int test_mme_mtk_vs_set_tx_cali_ind(hpav_chan_t *channel, int argc,
                                    char *argv[]);
int test_mme_vc_vs_set_sniffer_conf_req(hpav_chan_t *channel, int argc,
                                    char* argv[]);
int test_mme_vc_vs_set_remote_access_req(hpav_chan_t *channel, int argc,
                                    char* argv[]);
int test_mme_vc_vs_get_remote_access_req(hpav_chan_t *channel, int argc,
                                    char* argv[]);
#if !defined(_WIN32)
#include <sys/types.h>
#endif

int xorchecksum(void *src, u_int32_t size, u_int32_t *chksum);
