/* WiFi Example
 * Copyright (c) 2016 ARM Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mbed.h"
#include "TCPSocket.h"

#define WIFI_ESP8266    1
#define WIFI_IDW0XX1    2
#define WIFI_WIZFI310   3

#if TARGET_UBLOX_EVK_ODIN_W2
#include "OdinWiFiInterface.h"
OdinWiFiInterface wifi;

#elif TARGET_REALTEK_RTL8195AM
#include "RTWInterface.h"
RTWInterface wifi;

#else // External WiFi modules

#if MBED_CONF_APP_WIFI_SHIELD == WIFI_ESP8266
#include "ESP8266Interface.h"
ESP8266Interface wifi(MBED_CONF_APP_WIFI_TX, MBED_CONF_APP_WIFI_RX);
#elif MBED_CONF_APP_WIFI_SHIELD == WIFI_IDW0XX1
#include "SpwfSAInterface.h"
SpwfSAInterface wifi(MBED_CONF_APP_WIFI_TX, MBED_CONF_APP_WIFI_RX);
#elif MBED_CONF_APP_WIFI_SHIELD == WIFI_WIZFI310
#include "WizFi310Interface.h"
WizFi310Interface wifi(MBED_CONF_APP_WIFI_TX, MBED_CONF_APP_WIFI_RX);
#endif // MBED_CONF_APP_WIFI_SHIELD == WIFI_WIZFI310

#endif

#ifndef MBED_CFG_UDP_CLIENT_ECHO_BUFFER_SIZE
#define MBED_CFG_UDP_CLIENT_ECHO_BUFFER_SIZE 5
#endif

namespace {
    char tx_buffer[MBED_CFG_UDP_CLIENT_ECHO_BUFFER_SIZE] = {0};
    char rx_buffer[MBED_CFG_UDP_CLIENT_ECHO_BUFFER_SIZE] = {0};
    const char ASCII_MAX = '~' - ' ';
    const int ECHO_LOOPS = 16;
    char uuid[48] = {0};
}

void prep_buffer(char *uuid, char *tx_buffer, size_t tx_size) {
    size_t i = 0;

    memcpy(tx_buffer, uuid, strlen(uuid));
    i += strlen(uuid);

    tx_buffer[i++] = ' ';

    for (; i<tx_size; ++i) {
        tx_buffer[i] = (rand() % 10) + '0';
    }
}

void test_udp_echo(NetworkInterface *net)
{
    printf("UDP client IP Address is %s\n", net->get_ip_address());

    printf("target_ip %s\r\n", net->get_ip_address());
    char recv_key[] = "host_port";
    char ipbuf[60] = {0};
    char portbuf[16] = {0};
    unsigned int port = 5000;

    UDPSocket sock;
    sock.open(net);
    sock.set_timeout(500);

    //printf("MBED: UDP Server IP address received: %s:%d \n", ipbuf, port);
    nsapi_addr_t addr = {NSAPI_IPv4, 192,168,1,46};
    SocketAddress udp_addr(addr, port);

    int success = 0;
    for (int i=0; success < ECHO_LOOPS; i++)
    {
        prep_buffer(uuid, tx_buffer, sizeof(tx_buffer));
        const int ret = sock.sendto(udp_addr, tx_buffer, sizeof(tx_buffer));
        if (ret >= 0) {
            printf("[%02d] sent %d bytes - %.*s  \n", i, ret, ret, tx_buffer);
        } else {
            printf("[%02d] Network error %d\n", i, ret);
            continue;
        }

        SocketAddress temp_addr;
        const int n = sock.recvfrom(&temp_addr, rx_buffer, sizeof(rx_buffer));
        if (n >= 0) {
            printf("[%02d] recv %d bytes - %.*s  \n", i, n, n, rx_buffer);
        } else {
            printf("[%02d] Network error %d\n", i, n);
            continue;
        }

        if ((temp_addr == udp_addr &&
             n == sizeof(tx_buffer) &&
             memcmp(rx_buffer, tx_buffer, sizeof(rx_buffer)) == 0)) {
            success += 1;

            printf("[%02d] success #%d\n", i, success);
            continue;
        }

        // failed, clean out any remaining bad packets
        sock.set_timeout(0);
        while (true) {
            nsapi_size_or_error_t err = sock.recvfrom(NULL, NULL, 0);
            if (err == NSAPI_ERROR_WOULD_BLOCK) {
                break;
            }
        }
        sock.set_timeout(500);
    }
    sock.close();
    net->disconnect();
}

int main()
{
    int count = 0;

    printf("WiFi example\n\n");
    printf("\nConnecting to %s...\n", MBED_CONF_APP_WIFI_SSID);
    int ret = wifi.connect(MBED_CONF_APP_WIFI_SSID, MBED_CONF_APP_WIFI_PASSWORD, NSAPI_SECURITY_WPA_WPA2);
    if (ret != 0) {
        printf("\nConnection error\n");
        return -1;
    }

    printf("Success\n\n");
    printf("MAC: %s\n", wifi.get_mac_address());
    printf("IP: %s\n", wifi.get_ip_address());
    printf("Netmask: %s\n", wifi.get_netmask());
    printf("Gateway: %s\n", wifi.get_gateway());
    printf("RSSI: %d\n\n", wifi.get_rssi());

    test_udp_echo(&wifi);
    wifi.disconnect();
    printf("\nDone\n");
}
