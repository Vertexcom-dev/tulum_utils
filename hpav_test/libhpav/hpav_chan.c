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
// Implementation of channel management

// Avoid unnecessary warnings with VC
#define _CRT_SECURE_NO_WARNINGS 1

// Define this macro to get pcap_open macros
#define HAVE_REMOTE
#include "pcap.h"
#undef HAVE_REMOTE

#include "hpav_api.h"

// The channel just encapsulates a pcap_t* pointer
// To make the header file independent of libpcap (so users don't need to
// install pcap sdk) pcap_chan is just void* type.

// Opens a channel on given interface
// Populate error_stack if PCAP fails to open the channel
// Return NULL in this case to indicate an error occured
hpav_chan_t *hpav_open_channel(struct hpav_if *interface_to_open,
                               struct hpav_error **error_stack) {
    // Local variables
    hpav_chan_t *return_chan = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_chan = NULL;

    // Open interface with libpcap
    // 100 ms is to make sure we can frequently update timeout and check exit
    // conditions while sniffing
    pcap_chan = pcap_open_live(
        interface_to_open->name, 65535,
        PCAP_OPENFLAG_PROMISCUOUS | PCAP_OPENFLAG_NOCAPTURE_LOCAL, 100, errbuf);

    if (pcap_chan != NULL) {
        pcap_breakloop(pcap_chan);
        if (0 != pcap_setnonblock(pcap_chan, 1, errbuf)) {
            char buffer[PCAP_ERRBUF_SIZE + 128];
            sprintf(buffer, "PCAP errbuf : %s", errbuf);
            hpav_add_error(error_stack, hpav_error_category_network,
                           hpav_error_module_core, HPAV_ERROR_PCAP_ERROR,
                           "pcap_setnonblock failed", buffer);
            return NULL;
        }

        // Built returned structure
        return_chan = malloc(sizeof(hpav_chan_t));
        return_chan->pcap_chan = pcap_chan;
        memcpy(return_chan->mac_addr, interface_to_open->mac_addr,
               ETH_MAC_ADDRESS_SIZE);
        return return_chan;
    } else {
        // PCAP error
        char buffer[PCAP_ERRBUF_SIZE + 128];
        sprintf(buffer, "PCAP errbuf : %s", errbuf);
        hpav_add_error(error_stack, hpav_error_category_network,
                       hpav_error_module_core, HPAV_ERROR_PCAP_ERROR,
                       "pcap_open_live failed", buffer);
        return NULL;
    }
}

// Close channel
int hpav_close_channel(struct hpav_chan *channel) {
    // Close underlying pcap pointer
    pcap_close(channel->pcap_chan);

    free(channel);
    // pcap_close doesn't return anything. Return 0 here in all cases.
    return 0;
}
