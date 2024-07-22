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
// Implementation of interface management

// Avoid unnecessary warnings with VC on strcpy (strcpy_s could be used, but is
// not portable)
#define _CRT_SECURE_NO_WARNINGS 1
#ifdef WIN32
// Windows specific
// Including windows.h creates conflicts with pcap.h own headers ( ntddndis.h
// conflicts with the one from Windows)
#include <winsock2.h>
#include <Iphlpapi.h>
#else
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#endif

#include "hpav_api.h"
#include "pcap.h"

#ifdef WIN32

int hpav_populate_mac_addr(hpav_if_t **interfaces_list) {
    hpav_if_t *first_if = NULL;

    // Code exttracted from MSDN documentation
    PIP_ADAPTER_INFO pAdapterInfo = NULL;
    PIP_ADAPTER_INFO pAdapter = NULL;
    ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
    pAdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));

    if (interfaces_list != NULL) {
        first_if = *interfaces_list;
    } else {
        return -1;
    }

    // Make an initial call to GetAdaptersInfo to get
    // the necessary size into the ulOutBufLen variable
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);
    }

    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == NO_ERROR) {
        // We know have the list of adapters
        // Loop on the interfaces and for each of them find the corresponding
        // adapter if possible
        while (first_if != NULL) {
            // The interface description contains a prefix that we need to skip
            // to find {
            char *p_name = first_if->name;
            while (*p_name != '{' && *p_name != '\0') {
                p_name++;
            }
            if (p_name != NULL) {
                pAdapter = pAdapterInfo;
                while (pAdapter) {
                    if (strcmp(p_name, pAdapter->AdapterName) == 0 &&
                        pAdapter->AddressLength == ETH_MAC_ADDRESS_SIZE) {
                        memcpy(first_if->mac_addr, pAdapter->Address,
                               ETH_MAC_ADDRESS_SIZE);
                    }
                    pAdapter = pAdapter->Next;
                }
            }
            first_if = first_if->next;
        }
    }
    if (pAdapterInfo != NULL) {
        free(pAdapterInfo);
    }
    return 0;
}
#else
// Unix specific
int hpav_populate_mac_addr(hpav_if_t **interfaces_list) {
    hpav_if_t *first_if = NULL;
    unsigned int interface_num = 0;

    // Use ioctl on LINUX (this is not tested on other UNIX and will likely
    // fail)
    int temp_socket;
    struct ifreq ioctl_params;

    if (interfaces_list != NULL) {
        first_if = *interfaces_list;
    } else {
        return -1;
    }

    // Open socket
    temp_socket = socket(PF_INET, SOCK_DGRAM, 0);

    // Loop on all interfaces
    while (first_if != NULL) {
        // Reset params
        memset(&ioctl_params, 0, sizeof(struct ifreq));
        // Use interface name
        strncpy(ioctl_params.ifr_name, first_if->name, sizeof(ioctl_params.ifr_name) - 1);
        // Get MAC address
        ioctl(temp_socket, SIOCGIFHWADDR, &ioctl_params);

        // Check MAC address validity
        if (!memcmp(&ioctl_params.ifr_hwaddr.sa_data[0],
                    "\x00\x00\x00\x00\x00\x00", ETH_MAC_ADDRESS_SIZE)) {
            // Remove null MAC address from list of interfaces
            hpav_if_t *current_interface = first_if;
            if (interface_num == 0) {
                *interfaces_list = first_if->next;
            } else {
                (hpav_get_interface_by_index(*interfaces_list,
                                             interface_num - 1))
                    ->next = current_interface->next;
            }
            first_if = first_if->next;
            current_interface->next = NULL;
            free(current_interface->name);
            if (current_interface->description != NULL) {
                free(current_interface->description);
            }
            free(current_interface);
        } else {
            // Copy into interface data structure
            memcpy(first_if->mac_addr, &ioctl_params.ifr_hwaddr.sa_data[0],
                   ETH_MAC_ADDRESS_SIZE);
            first_if = first_if->next;
            interface_num++;
        }
    }

    // Close socket
    close(temp_socket);

    return 0;
}

#endif

// Get the list of interfaces compatible with libpcap
// Return an error if PCAP fails
// When no interface is returned (Linux without sudo) the caller is responsible
// for generating a higher level error is required.
int hpav_get_interfaces(hpav_if_t **interface_list,
                        struct hpav_error **error_stack) {
    // Local variables declaration
    pcap_if_t *pcap_interfaces = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    hpav_if_t *prev_if = NULL;
    hpav_if_t *new_if = NULL;
    hpav_if_t *first_if = NULL;
    int result = -1;
    hpav_if_t *cmp_if = NULL;

    // NULL is failure
    *interface_list = NULL;

    // Calls libpcap
    result = pcap_findalldevs(&pcap_interfaces, errbuf);
    if (result != 0) {
        char buffer[PCAP_ERRBUF_SIZE + 128];
        sprintf(buffer, "PCAP error code : %d, errbuf : %s", result, errbuf);
        hpav_add_error(error_stack, hpav_error_category_network,
                       hpav_error_module_core, HPAV_ERROR_PCAP_ERROR,
                       "pcap_findalldevs failed", buffer);
        return HPAV_ERROR_PCAP_ERROR;
    }

    // Copy data from libpcap into hpav data structures
    while (pcap_interfaces != NULL) {
#ifdef __linux__
        if ((strcmp("any", pcap_interfaces->name) != 0) &&
            (strncmp("nflog", pcap_interfaces->name, 5) != 0) &&
            (strncmp("usbmon", pcap_interfaces->name, 6) != 0) &&
            (pcap_interfaces->flags != PCAP_IF_LOOPBACK)) {
#else
        // On Windows, skip generic dialup interface. Winpcap cannot sendpacket
        // to this interface
        if (strcmp("\\Device\\NPF_GenericDialupAdapter",
                   pcap_interfaces->name) != 0) {
#endif
            // New hpav_if
            new_if = malloc(sizeof(hpav_if_t));
            // Initialise interface MAC address
            memset(new_if->mac_addr, 0, ETH_MAC_ADDRESS_SIZE);
            // Copy interface name
            new_if->name = malloc(strlen(pcap_interfaces->name) + 1);
            strcpy(new_if->name, pcap_interfaces->name);
            // Copy interface description (can be NULL)
            if (pcap_interfaces->description != NULL) {
                new_if->description =
                    malloc(strlen(pcap_interfaces->description) + 1);
                strcpy(new_if->description, pcap_interfaces->description);
            } else {
                new_if->description = NULL;
            }
            new_if->next = NULL;
            /* Sort interface by its name */
            if (first_if == NULL) {
                /* Record the first interface to send it back to the caller */
                first_if = new_if;
            } else if (strlen (new_if->name) < strlen (first_if->name) ||
                       (strlen (new_if->name) == strlen (first_if->name) &&
                        strcmp (new_if->name, first_if->name) < 0)) {
                /* Insert new_if before first_if */
                new_if->next = first_if;
                first_if = new_if;
            } else {
                prev_if = first_if;
                cmp_if = prev_if->next;
                while (cmp_if != NULL &&
                       (strlen (new_if->name) > strlen (cmp_if->name) ||
                        (strlen (new_if->name) == strlen (cmp_if->name) &&
                         strcmp (new_if->name, cmp_if->name) >= 0))) {
                    cmp_if = cmp_if->next;
                    prev_if = prev_if->next;
                }
                /* Insert new_if after prev_if */
                new_if->next = prev_if->next;
                prev_if->next = new_if;
            }
        }
        pcap_interfaces = pcap_interfaces->next;
    }

    // We don't need pcap interfaces anymore : free them
    pcap_freealldevs(pcap_interfaces);

    // Return a pointer to the first interface found
    *interface_list = first_if;

    // Populate MAC address (platform specific)
    hpav_populate_mac_addr(interface_list);

    return 0; // Success
}

// Free interfaces allocated by hpav_get_interfaces
int hpav_free_interfaces(struct hpav_if *interface_list) {
    while (interface_list != NULL) {
        struct hpav_if *current_interface = interface_list;
        free(interface_list->name);
        if (interface_list->description != NULL) {
            free(interface_list->description);
        }
        interface_list = interface_list->next;
        free(current_interface);
    }
    return 0;
}

struct hpav_if *hpav_get_interface_by_index(struct hpav_if *interfaces,
                                            unsigned int if_num) {
    struct hpav_if *current_interface = NULL;
    struct hpav_if *interface_result = NULL;
    unsigned int interface_num = 0;

    current_interface = interfaces;
    while (current_interface != NULL) {
        if (interface_num == if_num) {
            interface_result = current_interface;
        }
        current_interface = current_interface->next;
        interface_num++;
    }
    return interface_result;
}

unsigned int hpav_get_number_of_interfaces(struct hpav_if *interfaces) {
    struct hpav_if *current_interface = NULL;
    unsigned int interface_num = 0;

    current_interface = interfaces;
    while (current_interface != NULL) {
        current_interface = current_interface->next;
        interface_num++;
    }
    return interface_num;
}
