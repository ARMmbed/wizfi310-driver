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

#include "mbed.h"
#include "mbed_trace.h"
#include "mbed_events.h"
#include "netsocket/WiFiAccessPoint.h"
#include "RawSerial.h"
#include "Mutex.h"
#include "Semaphore.h"
#include "DigitalOut.h"
#include "Packet.h"

#define WIZFI310_SOCKET_COUNT       (8)

/** WizFi310Interface class.
 *  This is an interface to a WizFi310Interface radio.
 */
class WizFi310 {
public:
    enum socket_event_t {
        EventConnected,
        EventDataReceived,
        EventDataSent,
        EventDisconnected
    };
    union socket_event_data_t {
        struct socket_event_connected_t {
            int32_t error_code;
        } connected;
        struct socket_event_data_received_t {
            Packet *packet;
        } data_received;
        struct socket_event_data_sent_t {
            int32_t amount_or_error;
        } data_sent;
        struct socket_event_disconnected_t {

        } disconnected;
    };

    /**
     * Creates a new WizFir310 driver.
     * @param tx    Tx pin name.
     * @param rx    Rx pin name.
     * @param rts   Rts pin name.
     * @param cts   Cts pin name.
     * @param rst   Rst pin name.
     */
    WizFi310(PinName tx, PinName rx, PinName rts = NC, PinName cts = NC, PinName rst = NC);
    ~WizFi310();

    /**
     * Check firmware version of WizFi310
     *
     * @return character array firmware version or 0 if firmware query command gives outdated response
     * @warning This is only valid once the device is ready.
     */
    const char *get_firmware_version(void);

    /**
     * Enable/Disable DHCP
     *
     * @param enabled DHCP enabled when true
     * @return true only if WizFi310 enables/disables DHCP successfully
     */
    bool dhcp(bool enabled);

    /**
     * Attach a callback that will be invoked when the status changes.
     */
    void attach(Callback<void(nsapi_connection_status_t)> status_change_cb);

    /**
     * Connect WizFi310 to AP
     * @note This is blocking.
     *
     * @param ap the name of the AP
     * @param passPhrase the password of AP
     * @param security type of AP
     * @return see nsapi_error_t
     */
    nsapi_error_t connect(const char *ap, const char *passPhrase, const char *sec);

    /**
     * Returns the current connection status.
     *
     * @return Current connection status.
     */
    nsapi_connection_status_t status() const
    {
        return m_connection_status;
    }

    /**
     * Disconnect WizFi310 from AP
     *
     * @return see nsapi_error_t.
     */
    nsapi_error_t disconnect();

    /**
     *
     * @param ap_cb Called for each access point found. Last ap is NULL.
     * @return IN_PROGRESS or WOULD_BLOCK.
     */
    nsapi_error_t scan(Callback<void(nsapi_wifi_ap_t *)> ap_cb);


    const char *get_ip_address();
    int8_t get_rssi();

    /**
    * Open a socketed connection.
    * @note This is non-blocking.
    *
    * @param type the type of socket to open "UDP" or "TCP"
    * @param port port to open connection with
    * @param addr the IP address of the destination
    * @param callback     Function to call on state change
    * @param data         Argument to pass to callback
    * @note The callback is always called from the global event queue thread.
    * @return
    */
    int open(const char *type, const char *addr, int port, Callback<void(void *, socket_event_t, socket_event_data_t &)> callback, void *data);

    /**
    * Sends data to an open socket
    * @note This is non-blocking.
    *
    * @param id id of socket to send to
    * @param data data to be sent
    * @param amount amount of data to be sent
    * @return
    */
    int send(int id, const void *data, uint32_t amount);

    /**
    * Closes a socket
    * @note This is non-blocking.
    *
    * @param id id of socket to close, valid only 0-4
    * @return true only if socket is closed successfully
    */
    void close(int id);

    static const char *event2str(socket_event_t event)
    {
        switch (event) {
            case EventConnected:
                return "Connected";
            case EventDataReceived:
                return "Data received";
            case EventDataSent:
                return "Data sent";
            case EventDisconnected:
                return "Disconnected";
            default:
                return "Invalid event";
        }
    }

private:
    enum recv_state_t {
        Unknown,
        Ready,
        LinkUpGW,
        LinkUpIP,
        Status,
        Scan,
        Recv,
        RecvEnd,
        ResetRequired
    };
    static const char *recv_state2str(recv_state_t state)
    {
        switch (state) {
            case Unknown:
                return "Unknown";
            case Ready:
                return "Ready";
            case LinkUpGW:
                return "Link-Up GW";
            case LinkUpIP:
                return "Link-Up IP";
            case Status:
                return "Status";
            case Scan:
                return "Scan";
            case Recv:
                return "Recv";
            case RecvEnd:
                return "Recv end";
            case ResetRequired:
                return "Reset required";
            default:
                return "Invalid state";
        }
    }
    enum action_t {
        ActionNone,
        ActionBlocked,
        ActionDoReset,
        ActionDoConnect,
        ActionDoDisconnect,
        ActionDoStatus,
        ActionDoScan,
        ActionDoSOpen,
        ActionDoSSend,
        ActionDoSClose
    };
    static const char *action2str(action_t act)
    {
        switch (act) {
            case ActionNone:
                return "None";
            case ActionBlocked:
                return "Blocked";
            case ActionDoReset:
                return "Reset";
            case ActionDoConnect:
                return "Connect";
            case ActionDoDisconnect:
                return "Disconnect";
            case ActionDoScan:
                return "Scan";
            case ActionDoSOpen:
                return "SOpen";
            case ActionDoSSend:
                return "SSend";
            case ActionDoSClose:
                return "SClose";
            default:
                return "Invalid action";
        }
    }
    enum cmd_resp_t {
        CmdRspOk,
        CmdRspError,
        CmdRspErrorInvalidInput,
        CmdRspErrorInvalidScid,
        CmdRspErrorWifiStatus,
        CmdRspErrorModeStatus
    };
    struct socket_t {
        rtos::Mutex mutex;
        rtos::Semaphore evt;

        Packet *start;
        Packet **end;

        enum socket_status_t {
            StatusDisconnected,
            StatusConnecting,
            StatusConnected
        } volatile status;
        static const char *status2str(socket_status_t state)
        {
            switch (state) {
                case StatusDisconnected:
                    return "Disconnected";
                case StatusConnecting:
                    return "Connecting";
                case StatusConnected:
                    return "Connected";
                default:
                    return "Invalid state";
            }
        }

        Callback<void(void *, socket_event_t, socket_event_data_t &)> cbk;
        void *data;

        socket_t():
            mutex("socket_t"),
            evt(0, 1),
            start(NULL), end(&start),
            status(StatusDisconnected),
            cbk(NULL), data(NULL) {}

        void reset();
        void notify(socket_event_t evt, socket_event_data_t &data);
    };
    union cmd_ctx_u {
        struct connect_s {
            const char *ap;
            const char *pw;
            const char *sec;
            uint32_t attempt;
        } connect;
        struct sopen_s {
            socket_t *s;
        } sopen;
        struct ssend_s {
            socket_t *s;
            const void *data;
            uint32_t amount;
            bool did_send;
        } ssend;
        struct sclose_s {
            int id;
            bool done;
        } sclose;
    };

    // serial & lowlevel
    const PinName m_rst, m_rts, m_cts;
    DigitalOut m_nrst_pin;
    RawSerial m_serial;
    const bool m_has_hwfc;
    int m_rx_event_id;
    /// used for debug purposes
    volatile bool m_attached;

    volatile uint32_t m_isr_buf_len;
    uint8_t m_isr_buf[MBED_CONF_WIZFI310_RX_BUFFER_SIZE];

    uint32_t m_line_buf_len;
    uint8_t m_line_buf[MBED_CONF_WIZFI310_LINE_BUFFER_SIZE];

    // this buffer is not meant to keep data between call to serial_event.
    // it is meant to avoid potentially big stack allocation.
    uint8_t m_work_buf[MBED_CONF_WIZFI310_RX_BUFFER_SIZE];

    // state machine
    volatile uint32_t m_active_action;
    recv_state_t m_recv_state, m_prev_state;
    cmd_ctx_u m_cmd_ctx;

    Callback<void(const char[8])> m_greetings_cbk;
    Callback<void(cmd_resp_t)> m_on_cmd_end;
    Callback<void(nsapi_wifi_ap_t *ap)> m_scan_ap_cbk;
    Callback<void(nsapi_connection_status_t)> m_on_status_change;

    // sockets
    // One chain per socket.
    socket_t m_sockets[8];

    uint32_t m_data_to_receive;
    Packet *m_pending_packet;
    socket_t *m_pending_socket;
    volatile uint32_t m_heap_used;

    // misc
    Thread m_thread;
    events::EventQueue m_event_queue;
    nsapi_connection_status_t m_connection_status;

    // config
    bool m_dhcp;

    // information buffers
    char m_firmware_rev[8];
    char m_ip_buffer[16];
    char m_gateway_buffer[16];
    char m_netmask_buffer[16];
    char m_mac_buffer[18];
    int32_t m_rssi;

    void fatal_error(const char *msg);
    void serial_isr();
    void serial_event();
    bool recv_state_update(char *buf, uint32_t len);

    /**
     * Traces the command.
     *
     * @param fmt   format for the command.
     * @param ...   variadic arguments used with vprintf.
     */
    void trace_cmd(const char *fmt, ...);

    void heart_beat();
    void end_action();

    void do_reset();
    void do_echo_off(const char fw_rev[8]);
    void do_setup_serial(cmd_resp_t rsp);
    void do_set_access_point();
    void do_set_password(cmd_resp_t rsp);
    void do_set_dhcp(cmd_resp_t rsp);
    void do_join(cmd_resp_t rsp);
    void do_scan();
    void do_sclose(int id);

    void serial_setup_done(cmd_resp_t rsp);
    void join_done(cmd_resp_t rsp);
    void leave_done(cmd_resp_t rsp);
    void sopen_done(cmd_resp_t rsp);
    void ssend_done(cmd_resp_t rsp);
    void sclose_done(cmd_resp_t rsp);
    void device_ready(const char fw_rev[8]);

    void set_connection_status(nsapi_connection_status_t status);

    static nsapi_security_t str2sec(const char *str_sec);

    static bool parse_greeting(const char *buf, uint32_t len, char fw_ver[8]);
    static bool parse_error(const char *buf, uint32_t len, volatile cmd_resp_t &err);
    static bool parse_linkup_ip(const char *buf, uint32_t len, char ip[16]);
    static bool parse_linkup_gw(const char *buf, uint32_t len, char ip[16]);
    static bool parse_status(char *buf, uint32_t len, char ip_buf[16], char gw_buf[16], char mac_buf[18], int32_t &rssi);
    static bool parse_connect(const char *buf, uint32_t len, int &id);
    static bool parse_recv(const char *buf, uint32_t len, int &id, char ip_buf[16], uint16_t &port, uint32_t &plen);
    static bool parse_send_rdy(const char *buf, uint32_t len, int &id, uint32_t &plen);
    static bool parse_disconnect(const char *buf, uint32_t len, int &id);
    static bool parse_mac(const char *buf, uint32_t len, char mac_buf[18]);
    static bool parse_ip(const char *buf, uint32_t len, char ip_buf[16]);
    static bool parse_ap(char *buf, uint32_t len, nsapi_wifi_ap_t *ap);
    static const char *print_buf(const char *buf, uint32_t len);
};
#endif
