/* 
 * Copyright (c) 2015 ARM Limited
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

/**
  ******************************************************************************
  * @file    WizFi310.h
  * @author  Gateway Team
  * @brief   Header file of the WizFi310 WiFi Device
  ******************************************************************************
  * @attention
  *
  * THE PRESENT FIRMWARE WHICH IS FOR GUIDANCE ONLY AIMS AT PROVIDING CUSTOMERS
  * WITH CODING INFORMATION REGARDING THEIR PRODUCTS IN ORDER FOR THEM TO SAVE
  * TIME. AS A RESULT, WIZnet SHALL NOT BE HELD LIABLE FOR ANY
  * DIRECT, INDIRECT OR CONSEQUENTIAL DAMAGES WITH RESPECT TO ANY CLAIMS ARISING
  * FROM THE CONTENT OF SUCH FIRMWARE AND/OR THE USE MADE BY CUSTOMERS OF THE
  * CODING INFORMATION CONTAINED HEREIN IN CONNECTION WITH THEIR PRODUCTS.
  *
  * <h2><center>&copy; COPYRIGHT 2017 WIZnet Co.,Ltd.</center></h2>
  ******************************************************************************
  */

#ifndef WIZFI310_H_
#define WIZFI310_H_

#include "ATCmdParser.h"
#include "netsocket/WiFiAccessPoint.h"
#include "UARTSerial.h"
#include "nsapi_types.h"
#include "rtos.h"

/** WizFi310Interface class.
    This is an interface to a WizFi310Interface radio.
*/
class WizFi310
{
public:
    WizFi310(PinName tx, PinName rx, PinName rts, PinName cts, bool debug=false);

    /**
    * Check firmware version of WizFi310
    *
    * @return character array firmware version or 0 if firmware query command gives outdated response
    */
    const char* get_firmware_version(void);
    
    /**
    * Startup the WizFi310
    *
    * @param mode mode of WIFI 0-client, 1-host
    * @return true only if WizFi310 was setup correctly
    */
    bool startup(int mode);

    /**
    * Reset WizFi310
    *
    * @return true only if WizFi310 resets successfully
    */
    bool reset(void);

    /**
    * Enable/Disable DHCP
    *
    * @param enabled DHCP enabled when true
    * @return true only if WizFi310 enables/disables DHCP successfully
    */
    bool dhcp(bool enabled);

    /**
    * Connect WizFi310 to AP
    *
    * @param ap the name of the AP
    * @param passPhrase the password of AP
    * @param security type of AP
    * @return true only if WizFi310 is connected successfully
    */
    bool connect(const char *ap, const char *passPhrase, const char *sec);

    /**
    * Disconnect WizFi310 from AP
    *
    * @return true only if WizFi310 is disconnected successfully
    */
    bool disconnect(void);

    /**
    * Get the IP address of WizFi310
    *
    * @return null-teriminated IP address or null if no IP address is assigned
    */
    const char *getIPAddress(void);

    /**
    * Get the MAC address of WizFi310
    *
    * @return null-terminated MAC address or null if no MAC address is assigned
    */
    const char *getMACAddress(void);

     /** Get the local gateway
     *
     *  @return         Null-terminated representation of the local gateway
     *                  or null if no network mask has been recieved
     */
    const char *getGateway();

    /** Get the local network mask
     *
     *  @return         Null-terminated representation of the local network mask 
     *                  or null if no network mask has been recieved
     */
    const char *getNetmask();

    /* Return RSSI for active connection
     *
     * @return      Measured RSSI
     */
    int8_t getRSSI();

    /**
    * Check if WizFi310 is conenected
    *
    * @return true only if the chip has an IP address
    */
    bool isConnected(void);

    /** Scan for available networks
     *
     * @param  ap    Pointer to allocated array to store discovered AP
     * @param  limit Size of allocated @a res array, or 0 to only count available AP
     * @return       Number of entries in @a res, or if @a count was 0 number of available networks, negative on error
     *               see @a nsapi_error
     */
    int scan(WiFiAccessPoint *res, unsigned limit);
    
    /**Perform a dns query
    *
    * @param name Hostname to resolve
    * @param ip   Buffer to store IP address
    * @return 0 true on success, false on failure
    */
    bool dns_lookup(const char *name, char *ip);

    /**
    * Open a socketed connection
    *
    * @param type the type of socket to open "UDP" or "TCP"
    * @param id id to give the new socket, valid 0-4
    * @param port port to open connection with
    * @param addr the IP address of the destination
    * @return true only if socket opened successfully
    */
    bool open(const char *type, int id, const char* addr, int port);

    /**
    * Sends data to an open socket
    *
    * @param id id of socket to send to
    * @param data data to be sent
    * @param amount amount of data to be sent - max 1024
    * @return true only if data sent successfully
    */
    bool send(int id, const void *data, uint32_t amount);

    /**
    * Receives stream data from an open TCP socket
    *
    * @param id id to receive from
    * @param data placeholder for returned information
    * @param amount number of bytes to be received
    * @return the number of bytes received
    */
    int32_t recv_tcp(int id, void *data, uint32_t amount);

    /**
    * Receives datagram from an open UDP socket
    *
    * @param id id to receive from
    * @param data placeholder for returned information
    * @param amount number of bytes to be received
    * @return the number of bytes received
    */
    int32_t recv_udp(int id, void *data, uint32_t amount);

    /**
    * Closes a socket
    *
    * @param id id of socket to close, valid only 0-4
    * @return true only if socket is closed successfully
    */
    bool close(int id);

    /**
    * Allows timeout to be changed between commands
    *
    * @param timeout_ms timeout of the connection
    */
    void setTimeout(uint32_t timeout_ms);

    /**
    * Checks if data is available
    */
    bool readable();

    /**
    * Checks if data can be written
    */
    bool writeable();

    /**
    * Attach a function to call whenever network state has changed
    *
    * @param func A pointer to a void function, or 0 to set as none
    */
    void attach(mbed::Callback<void()> func);

    /**
    * Attach a function to call whenever network state has changed
    *
    * @param obj pointer to the object to call the member function on
    * @param method pointer to the member function to call
    */
    template <typename T, typename M>
    void attach(T *obj, M method) {
        attach(mbed::Callback<void()>(obj, method));
    }

private:
    mbed::UARTSerial _serial;
    mbed::ATCmdParser _parser;

    PinName _rts;
    PinName _cts;

    struct packet {
        struct packet *next;
        int id;
        uint32_t len;
        // data follows
        char *data;
		packet( int new_id, uint32_t new_len): next(NULL), id(new_id), len(new_len) {
            this->data = new char[this->len];
        }
        ~packet() {
            delete this->data;
        }
    } *_packets, **_packets_end;
    void _packet_handler();
    //void _socket_close_handler();
    bool recv_ap(nsapi_wifi_ap_t *ap);
    nsapi_security_t str2sec(const char *str_sec);
    int hex_str_to_int(const char* hex_str);

    char _ip_buffer[16];
    char _gateway_buffer[16];
    char _netmask_buffer[16];
    char _mac_buffer[18];
    char _firmware_version[8];

    int  _op_mode;      // 0 : Station Mode, 1 : AP Mode
    bool _dhcp;
    uint32_t _timeout_ms;
};

#endif
