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
  * @file    WizFi310.cpp
  * @author  Gateway Team
  * @brief   Implementation file of the WizFi310 WiFi Device
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

/*
 * Notes:
 *  Assumptions:
 *  - command terminations are "[OK]" or "[ERROR%[^\]]]" .
 *
 *  Notes:
 *  - reception notification may arrive at anytime even in the middle of a response such as wstatus report.
 *
 *  Strategies:
 *  - All reads to the serial line are done in the event queue thread context
 *  - All callbacks are invoked from the event queue thread context.
 *  - A limit is set to the amount of received payload.
 *  - If hardware flow control (hwfc) is present, any further reception/command will be paused until the buffer gets read.
 *  - If no hwfc is available, the affected socket gets closed and the incomming packets are ignored/dropped.
 *
 *  Failure handling :
 *  - If a command times out, the module is considered out of sync and operations are stopped until next module reset.
 *  - If an unrecognized sequence of characters is received the driver stops all operation until
 *    a reset is operated. This is to prevent any risk of received data being interpreted as being module's response when it is not.
 *
 * Known issues :
 * - Ideally the reset should be hardware as detection through the greeting message may be spooffed by malicious incoming data.
 * - Because the module may send a reception event at anytime (even in the middle of a reception) if an SSID or some other
 *   user/envirenmentaly controled input contains something similar to the recv header, it may open gate to malicious packet
 *   injection.
 *
 * Author: Wilfried Chauveau
 */

/**
 * @TODO:
 * - [ ] analyze event queue usage and adjust its default size.
 * - [ ] analyze dispatch thread usage and adjust its default stack size.
 * - [ ] overhaul the event_serial & recv_state_update functions
 * - [ ] review error detection & handling & make sure all case are covered.
 * - [ ] complete doxygenation
 * - [ ] add support for non-dhcp/static ip mode
 * - [ ] add support for listen socket
 * - [ ] add support for thread safe ip/rssi/gateway reading
 */

#include "mbed.h"
#include "mbed_trace.h"
#include "WizFi310.h"
#include "DigitalOut.h"

#define TRACE_GROUP                     "WZFI"

#define WIZFI310_DEFAULT_BAUD_RATE     115200

#define AT_CMD_PARSER_DEFAULT_TIMEOUT     500
#define AT_CMD_PARSER_INIT_TIMEOUT       1000
#define AT_CMD_PARSER_RECV_TIMEOUT      20000

#define send_command(...) { trace_cmd(__VA_ARGS__); m_serial.printf(__VA_ARGS__); }

using namespace mbed;

// =================================================================================================
// Utility functions
static void consume(uint8_t *to, uint8_t *from, volatile uint32_t &from_len, uint32_t amount)
{
    memcpy(to, from, amount);
    from_len -= amount;
    memmove(from, from + amount, from_len);
}

// =================================================================================================
// Driver implementation
WizFi310::WizFi310(PinName tx, PinName rx, PinName rts, PinName cts, PinName rst) :
    m_rst(rst), m_rts(rts), m_cts(cts), m_nrst_pin(rst, 0),
    m_serial(tx, rx, WIZFI310_DEFAULT_BAUD_RATE),
    m_has_hwfc((rts != NC) && (cts != NC)),
    m_rx_event_id(0), m_attached(false), m_isr_buf_len(0), m_line_buf_len(0),
    m_active_action(ActionBlocked),
    m_recv_state(Unknown),
    m_greetings_cbk(NULL), m_on_cmd_end(NULL),
    m_data_to_receive(0), m_pending_packet(NULL), m_pending_socket(NULL), m_heap_used(0),
    m_thread(osPriorityNormal, MBED_CONF_WIZFI310_STACKSIZE, NULL, "wizfi310_driver"),
    m_event_queue(MBED_CONF_WIZFI310_EVENT_QUEUE_SIZE),
    m_connection_status(NSAPI_STATUS_DISCONNECTED),
    m_dhcp(true)
{
    if (rst != NC) {
        m_nrst_pin = 0; // force reset on instanciation to match the default states.
    }

    m_thread.start(Callback<void()>(&m_event_queue, &EventQueue::dispatch_forever));
    m_event_queue.call_every(2000, this, &WizFi310::heart_beat);
}

WizFi310::~WizFi310()
{
    // TODO: we may want to gracefully shut down sockets
    // we may also want to gracefully disconnect the device and activate the
    // hw reset if any was provided.
    m_event_queue.break_dispatch();
    m_thread.join();
}

void WizFi310::attach(Callback<void(nsapi_connection_status_t)> status_change_cb)
{
    m_on_status_change = status_change_cb;
}

bool WizFi310::dhcp(bool enabled)
{
    // We should probably not accept a true here if the other parameters are not set.
    m_dhcp = enabled;
    return m_dhcp;
}

nsapi_error_t WizFi310::scan(Callback<void(nsapi_wifi_ap_t *)> ap_cb)
{
    core_util_critical_section_enter();
    action_t action = (action_t)m_active_action;
    if ((action == ActionNone) || (action == ActionBlocked)) {
        m_active_action = ActionDoScan;
        core_util_critical_section_exit();
    } else {
        core_util_critical_section_exit();
        return NSAPI_ERROR_WOULD_BLOCK;
    }

    m_scan_ap_cbk = ap_cb;

    if (action == ActionBlocked) {
        m_event_queue.call(this, &WizFi310::do_reset);
    } else {
        m_event_queue.call(this, &WizFi310::do_scan);
    }

    return NSAPI_ERROR_IN_PROGRESS;
}

nsapi_error_t WizFi310::connect(const char *ap, const char *passPhrase, const char *sec)
{
    tr_info("%s|%s setting credentials: (%s) \"%s\":\"%s\"", recv_state2str(m_recv_state), action2str((action_t)m_active_action), sec, ap, passPhrase);

    if ((ap == NULL) || (strlen(ap) == 0)) {
        return NSAPI_ERROR_NO_SSID;
    }

    if (m_connection_status == NSAPI_STATUS_GLOBAL_UP) {
        return NSAPI_ERROR_OK;
    }

    core_util_critical_section_enter();
    action_t action = (action_t)m_active_action;
    if ((action != ActionNone) && (action != ActionBlocked)) {
        core_util_critical_section_exit();
        return NSAPI_ERROR_WOULD_BLOCK;
    }
    m_active_action = ActionDoConnect;
    core_util_critical_section_exit();

    this->set_connection_status(NSAPI_STATUS_CONNECTING);

    m_cmd_ctx.connect.ap = ap;
    m_cmd_ctx.connect.pw = passPhrase;
    m_cmd_ctx.connect.sec = sec;
    m_cmd_ctx.connect.attempt = 0;

    if (action == ActionBlocked) {
        m_event_queue.call(this, &WizFi310::do_reset);
    } else {
        m_event_queue.call(this, &WizFi310::do_set_access_point);
    }
    // TODO: Do we want a time out there ?
    return NSAPI_ERROR_IN_PROGRESS;
}

nsapi_error_t WizFi310::disconnect()
{
    if (m_connection_status == NSAPI_STATUS_DISCONNECTED) {
        return NSAPI_ERROR_NO_CONNECTION;
    }
    uint32_t expected_current = ActionNone;
    if (!core_util_atomic_cas_u32(&m_active_action, &expected_current, ActionDoDisconnect)) {
        return NSAPI_ERROR_WOULD_BLOCK;
    }

    m_on_cmd_end = Callback<void(cmd_resp_t)>(this, &WizFi310::leave_done);
    send_command("AT+WLEAVE\r");
    return NSAPI_ERROR_IN_PROGRESS;
}

int WizFi310::open(const char *type, const char *addr, int port, Callback<void(void *, socket_event_t, socket_event_data_t &)> callback, void *data)
{
    uint32_t expected = ActionNone;
    tr_debug("::open(%s, %s, %d){%s|%s}", type, addr, port, recv_state2str(m_recv_state), action2str((action_t)m_active_action));
    if (!core_util_atomic_cas_u32(&m_active_action, &expected, ActionDoSOpen)) {
        return NSAPI_ERROR_WOULD_BLOCK;
    }

    // try to guess the id used.
    int id = 0;
    socket_t *s = NULL;
    for (; id < WIZFI310_SOCKET_COUNT; id++) {
        s = &m_sockets[id];
        if (s->status == socket_t::StatusDisconnected) {
            break;
        }
    }
    if (id < WIZFI310_SOCKET_COUNT) {
        s->mutex.lock();
        s->reset();
        s->status = socket_t::StatusConnecting;
        s->cbk = callback;
        s->data = data;
        s->mutex.unlock();

        m_cmd_ctx.sopen.s = s;
        m_on_cmd_end = Callback<void(cmd_resp_t)>(this, &WizFi310::sopen_done);
        send_command("AT+SCON=O,%s,%s,%d,,0\r", type, addr, port);
        // TODO: shall we setup a time out there ?
        tr_info("expecting connect on: %d", id);
    } else {
        end_action();
        id = -1;
    }
    return id;
}

nsapi_error_t WizFi310::send(int id, const void *data, uint32_t amount)
{
    if ((id > 7) || (id < 0) || (data == NULL)) {
        return NSAPI_ERROR_PARAMETER;
    }
    if (amount == 0) {
        return NSAPI_ERROR_OK;
    }

    uint32_t expected = ActionNone;
    if (!core_util_atomic_cas_u32(&m_active_action, &expected, ActionDoSSend)) {
        return NSAPI_ERROR_WOULD_BLOCK;
    }
    socket_t *s = &m_sockets[id];

    if (s->status != socket_t::StatusConnected) {
        end_action();
        return NSAPI_ERROR_NO_CONNECTION;
    }

    m_cmd_ctx.ssend.s = s;
    m_cmd_ctx.ssend.data = data;
    m_cmd_ctx.ssend.amount = amount;
    m_cmd_ctx.ssend.did_send = false;
    m_on_cmd_end = Callback<void(cmd_resp_t)>(this, &WizFi310::ssend_done);
    send_command("AT+SSEND=%d,,,%lu\r", id, amount);
    return NSAPI_ERROR_IN_PROGRESS;
}

void WizFi310::close(int id)
{
    tr_info("::close(%d)", id);
    if ((id < 0) || (id > 7)) {
        return;
    }

    socket_t *s = &m_sockets[id];
    // detach callbacks
    s->mutex.lock();
    s->cbk = NULL;
    s->data = NULL;
    s->mutex.unlock();
    int evtid = m_event_queue.call(this, &WizFi310::do_sclose, id);
    tr_debug("enqueue do_sclose: %d", evtid);
    MBED_ASSERT(evtid != 0);
}

// =================================================================================================
// private methods
void WizFi310::heart_beat()
{
    tr_debug("%s|%s attached: %d rxevtid: %d", recv_state2str(m_recv_state), action2str((action_t)m_active_action), m_attached, m_rx_event_id);
    if (m_data_to_receive != 0) {
        tr_debug("pending socket: %lu to_recv: %lu", (((uint32_t)m_pending_socket) - (uint32_t)(m_sockets)) / sizeof(socket_t), m_data_to_receive);
    }

    if (m_rx_event_id != 0) {
        tr_debug("tick: %u time left: %d", m_event_queue.tick(), m_event_queue.time_left(m_rx_event_id));
    }
    tr_debug("isr_buf_len: %lu line: (%lu) %.*s", m_isr_buf_len, m_line_buf_len, m_line_buf_len, m_line_buf);

    // TODO: This shall not be required and is here solely for debug purposed.
    // attach serial
    // if it has been detached, force enqueueing the serial_event (could aswell call it from here ...)
    if (!m_attached) {
        m_attached = true;
        m_serial.attach(Callback<void()>(this, &WizFi310::serial_isr));
    }
    core_util_critical_section_enter();
    if (m_rx_event_id == 0) {
        // TODO: If m_rx_event_id == 0 means that we failed at scheduling the event the previous time.
        // Shall we loop until it's actually enqueued ?
        m_rx_event_id = m_event_queue.call(this, &WizFi310::serial_event);
    }
    core_util_critical_section_exit();
}

void WizFi310::set_connection_status(nsapi_connection_status_t status)
{
    bool has_changed = m_connection_status != status;
    if (has_changed) {
        tr_debug("Wifi status change: %d", status);
        m_connection_status = status;
        if (m_on_status_change) {
            m_on_status_change(status);
        }
    }
}

// Runs from an isr context.
// This kind of emulates what a dma would do
void WizFi310::serial_isr()
{
    if (m_rx_event_id == 0) {
        // TODO: If m_rx_event_id == 0 means that we failed at scheduling the event the previous time.
        // Shall we loop until it's actually enqueued ?
        m_rx_event_id = m_event_queue.call(this, &WizFi310::serial_event);
    }
    if ((m_isr_buf_len >= MBED_CONF_WIZFI310_RX_BUFFER_SIZE) && m_has_hwfc) {
        m_serial.attach(NULL); // if buffer full, detach isr, it will be reattached later
        m_attached = false;
        return;
    }
    int input = -1;
    // .getc() contains a loop on readable. we don't want to get stuck in it from an interrupt.
    if (m_serial.readable()) {
        input = m_serial.getc();
    }
    if (input < 0) {
        // TODO: do we want to catch that ?
        // Most probably yes.
        return;
    }

    if (m_isr_buf_len < MBED_CONF_WIZFI310_RX_BUFFER_SIZE) {
        m_isr_buf[m_isr_buf_len] = (char)input;
        m_isr_buf_len += 1;
    } else {
        // Overrun is flagged in the serial_event.
    }
}

void WizFi310::fatal_error(const char *msg)
{
    m_active_action = ActionBlocked;

    m_serial.attach(NULL);
    m_attached = false;

    m_recv_state = ResetRequired;

    tr_error("Fatal error: %s", msg);
}

// runs from the global event queue context.
void WizFi310::serial_event()
{
    m_rx_event_id = 0;
    while (true) {
        tr_debug("isr_buf_len: %lu line: (%lu) %.*s", m_isr_buf_len, m_line_buf_len, m_line_buf_len, m_line_buf);
        uint8_t *buf = m_work_buf;
        uint32_t len = 0;
        bool has_line = (m_line_buf_len != 0) && ((m_line_buf[m_line_buf_len - 1] == '\r') || (m_line_buf[m_line_buf_len - 1] == '\n'));
        bool has_recv = false;

        if (!has_line) {
            // TODO: simplify/rationalize this, it is too complex to sit here
            // the ratio indentation/line count is 
            core_util_critical_section_enter();
            switch (m_recv_state) {
                case ResetRequired:
                    break;
                case Recv: {
                    if ((m_pending_packet != NULL) || !m_has_hwfc) {
                        // extract as much as needed to exhaust the current packet.
                        if (m_data_to_receive > m_isr_buf_len) {
                            len = m_isr_buf_len;
                        } else {
                            len = m_data_to_receive;
                        }
                    }

                    // consume len from m_isr_buf
                    // has no effect is len == 0.
                    consume(buf, m_isr_buf, m_isr_buf_len, len);
                    break;
                }
                case RecvEnd: {
                    if (m_isr_buf_len >= 2) {
                        m_isr_buf_len -= 2;
                        memmove(m_isr_buf, m_isr_buf + 2, m_isr_buf_len);
                        core_util_critical_section_exit();
                        m_recv_state = m_prev_state;
                        continue;
                    }
                    break;
                }
                default: {
                    // search for recv event or eol
                    uint8_t *ptr = NULL;
                    for (uint32_t i = 0; i < m_isr_buf_len; i++) {
                        if ((m_isr_buf[i] == '{') || (m_isr_buf[i] == '\r') || (m_isr_buf[i] == '\n')) {
                            ptr = &m_isr_buf[i];
                            break;
                        }
                    }

                    if (ptr != NULL) {
                        has_recv = *ptr == '{';
                        has_line = !has_recv;
                        len = ptr - m_isr_buf;

                        // if we matched an eol, then include it in the copy.
                        if (has_line) {
                            len += 1;
                        }
                    }
                    if ((m_line_buf_len + len) > MBED_CONF_WIZFI310_LINE_BUFFER_SIZE) {
                        core_util_critical_section_exit();
                        this->fatal_error("Line buffer overrun");
                        return;
                    }
                    consume(m_line_buf + m_line_buf_len, m_isr_buf, m_isr_buf_len, len);
                    m_line_buf_len += len;

                    if (m_isr_buf[0] == '{') {
                        ptr = (uint8_t *)memchr(m_isr_buf, '}', m_isr_buf_len);
                        has_recv &= ptr != NULL;
                        if (has_recv) {
                            len = (ptr - m_isr_buf) + 1;
                            consume(buf, m_isr_buf, m_isr_buf_len, len);
                        } else {
                            len = 0;
                        }
                    }
                    if (!has_line && !has_recv && (m_isr_buf_len == MBED_CONF_WIZFI310_RX_BUFFER_SIZE)) {
                        core_util_critical_section_exit();
                        this->fatal_error("rx buffer overrun");
                        return;
                    }
                    break;
                }
            }
            core_util_critical_section_exit();
        }

        if (!has_recv && has_line) {
            buf = m_line_buf;
            len = m_line_buf_len;
        }

        if ((m_recv_state == Recv) && ((len != 0) || (m_pending_packet == NULL))) {
            // if we are in recv mode and we either read something or we need to allocated a packet, proceed to the recv_state_update method.
            if (this->recv_state_update((char *)buf, len)) {
                // if recv_state_update returns false, we exit the loop and come back later.
                // this shall only happen if m_recv_state == recv & m_pending_packet == null.
                break;
            }
        } else if (has_line || has_recv) {
            // if we found an recv header or a complete line
            //      clear the eol if any
            //      proceed to recv_state_update.
            if ((buf[0] != '{') && ((buf[len - 1] == '\n') || (buf[len - 1] == '\r'))) {
                len -= 1; // remove eol byte from the line.
            }
            if (len != 0) {
                buf[len] = '\0';
                this->recv_state_update((char *)buf, len);
            }
            if (has_line) {
                m_line_buf_len = 0;
            }
        } else {
            // we're done (not enough data), break the loop.
            break;
        }
    }
    m_attached = true;
    m_serial.attach(Callback<void()>(this, &WizFi310::serial_isr));
}

// TODO: make this cleaner,
// An array of callback using the recv_state_t as an index could be a nicer dispatch tool than this big switch.
bool WizFi310::recv_state_update(char *buf, uint32_t len)
{
    int id;
    char fw_rev[9] = {0};
    char ip[16] = {0};
    uint16_t port;
    uint32_t plen;

    if (m_recv_state != Recv) {
        tr_info("%s|%s: received: (%3lu) %.*s", recv_state2str(m_recv_state), action2str((action_t)m_active_action), len, (int)len, buf);
        if (this->parse_recv(buf, len, id, ip, port, plen)) {
            // tr_debug("recv: %d (%s:%hu): %lu", id, ip, port, plen);
            m_data_to_receive = plen;
            m_pending_socket = &m_sockets[id];
            // TODO: update socket's ip/port
            m_prev_state = m_recv_state;
            m_recv_state = Recv;
            return false;
        }

    } else {
        // tr_info("%s|%s: received: (%3lu) %s", recv_state2str(m_recv_state), action2str((action_t)m_active_action), len, print_buf(buf, len));
        // tr_info("%s|%s: received: (%3lu) <bin>", recv_state2str(m_recv_state), action2str((action_t)m_active_action), len);
    }

    switch (m_recv_state) {
        case Unknown: {
            if (this->parse_greeting(buf, len, fw_rev)) {
                if (m_greetings_cbk) {
                    m_greetings_cbk(fw_rev);
                }
            } else {
                // ignore unexpected messaages
            }
            break;
        }
        case LinkUpIP: {
            if (this->parse_linkup_ip(buf, len, m_ip_buffer)) {
                m_recv_state = LinkUpGW;
            } else {
                tr_warn("unexpected: %.*s", (int)len, buf);
                this->fatal_error("Unexpected message");
            }
            break;
        }
        case LinkUpGW: {
            if (this->parse_linkup_gw(buf, len, m_gateway_buffer)) {
                this->set_connection_status(NSAPI_STATUS_GLOBAL_UP);
                m_recv_state = Ready;
            } else {
                tr_warn("unexpected: %.*s", (int)len, buf);
                this->fatal_error("Unexpected message");
            }
            break;
        }
        case Status: {
            int32_t t;
            if (this->parse_status(buf, len, m_ip_buffer, m_gateway_buffer, m_mac_buffer, t)) {
                m_rssi = t;
                m_recv_state = Ready;
            } else {
                tr_warn("Unexpected: %.*s", (int)len, buf);
                this->fatal_error("Unexpected message");
            }
            break;
        }
        case Scan: {
            nsapi_wifi_ap_t ap = {0};
            if (this->parse_ap(buf, len, &ap)) {
                if (m_scan_ap_cbk) {
                    m_scan_ap_cbk(&ap);
                }
            } else if (strcmp(buf, "[OK]") == 0) {
                if (m_scan_ap_cbk) {
                    m_scan_ap_cbk(NULL);
                }
                this->end_action();
                m_recv_state = Ready;
            } else {
                tr_warn("Unexpected: %.*s", (int)len, buf);
                this->fatal_error("Unexpected message");
            }
            break;
        }
        case Recv: {
            if (m_pending_packet == NULL) {
                if ((m_heap_used + m_data_to_receive) >= MBED_CONF_WIZFI310_MAX_HEAP_USAGE) {
                    tr_warn("cannot allocate yet, wait for next attempt");
                    return true;
                } else {
                    m_pending_packet = Packet::new_packet(m_data_to_receive, m_heap_used);
                    if (!m_has_hwfc && (m_pending_packet == NULL)) {
                        // TODO: dropping data for this socket, we may want to close it
                    }
                }
            }
            if ((m_pending_packet != NULL) && (len != 0)) {
                Packet *p = m_pending_packet;
                MBED_ASSERT(p->append(buf, len) == len);
                m_data_to_receive -= len;

                if (m_data_to_receive == 0) {
                    socket_t *s = m_pending_socket;

                    m_recv_state = RecvEnd;
                    m_pending_packet = NULL;
                    m_pending_socket = NULL;

                    socket_event_data_t data;
                    data.data_received.packet = p;
                    s->notify(EventDataReceived, data);
                }
            }
            break;
        }
        default: {
            cmd_resp_t rsp;
            if (this->parse_greeting(buf, len, fw_rev)) {
                if (m_greetings_cbk) {
                    m_greetings_cbk(fw_rev);
                }
            } else if (strcmp(buf, "[OK]") == 0) {
                if (m_on_cmd_end) {
                    Callback<void(cmd_resp_t)> cbk = m_on_cmd_end;
                    m_on_cmd_end = NULL;
                    cbk(CmdRspOk);
                }
            } else if (strncmp(buf, "AT", 2) == 0) {
                // echo enabled
            } else if (this->parse_error(buf, len, rsp)) {
                tr_debug("Error: %d", rsp);
                if (m_on_cmd_end) {
                    Callback<void(cmd_resp_t)> cbk = m_on_cmd_end;
                    m_on_cmd_end = NULL;
                    cbk(rsp);
                }
            } else if (strcmp(buf, "[Link-Up Event]") == 0) {
                m_recv_state = LinkUpIP;
            } else if (strcmp(buf, "[Link-Down Event]") == 0) {
                if ((m_connection_status != NSAPI_STATUS_CONNECTING) || (m_cmd_ctx.connect.attempt == MBED_CONF_WIZFI310_CONNECT_MAX_ATTEMPT)) {
                    this->set_connection_status(NSAPI_STATUS_DISCONNECTED);
                }
                // we may as well want to reset all sockets.
            } else if (strcmp(buf, "IF/SSID/IP-Addr/Gateway/MAC/TxPower(dBm)/RSSI(-dBm)") == 0) {
                MBED_ASSERT(m_active_action == ActionDoStatus);
                m_recv_state = Status;
            } else if (strcmp(buf, "Index/SSID/BSSID/RSSI(-dBm)/MaxDataRate(Mbps)/Security/RadioBand(GHz)/Channel") == 0) {
                MBED_ASSERT(m_active_action == ActionDoScan);
                m_recv_state = Scan;
            } else if (this->parse_connect(buf, len, id)) {
                socket_t *s = &m_sockets[id];
                s->mutex.lock();
                if (s->status != socket_t::StatusConnecting) {
                    tr_warn("Unexpected connection on socket %d", id);
                } else if (m_active_action == ActionDoSOpen) {
                    end_action();
                }
                s->status = socket_t::StatusConnected;
                socket_event_data_t data;
                s->notify(EventConnected, data);
                s->mutex.unlock();
            } else if (this->parse_disconnect(buf, len, id)) {
                socket_t *s = &m_sockets[id];
                uint32_t act = m_active_action;

                s->mutex.lock();
                if (s->status == socket_t::StatusDisconnected) {
                    tr_warn("Socket %d is already disconnected", id);
                } else {
                    // tr_debug("act: %s s->status: %s", action2str((action_t)act), socket_t::status2str(s->status));
                    if ((act == ActionDoSOpen) && (s->status == socket_t::StatusConnecting)) {
                        end_action();
                    } else {
                        if ((act == ActionDoSClose) && (id == m_cmd_ctx.sclose.id)) {
                            if (m_cmd_ctx.sclose.done) {
                                end_action();
                            } else {
                                m_cmd_ctx.sclose.id = -1;
                            }
                        }
                    }
                }
                if (s->status != socket_t::StatusDisconnected) {
                    s->status = socket_t::StatusDisconnected;
                    socket_event_data_t data;
                    s->notify(EventDisconnected, data);
                }
                // tr_debug("act: %s s->status: %s", action2str((action_t)m_active_action), socket_t::status2str(s->status));
                s->mutex.unlock();
            } else if (this->parse_send_rdy(buf, len, id, plen)) {
                MBED_ASSERT(m_active_action == ActionDoSSend);
                MBED_ASSERT(plen == m_cmd_ctx.ssend.amount);
                const char *data = (const char *)m_cmd_ctx.ssend.data;
                // tr_debug("Sending on %d: %s", id, print_buf(data, plen));
                for (uint32_t i = 0; i < plen; i++) {
                    m_serial.putc(*data);
                    data++;
                }
                m_cmd_ctx.ssend.did_send = true;
                // send completion is signal by [OK].
            } else if (this->parse_mac(buf, len, m_mac_buffer)) {
                // TODO: anything to do here ?
            } else if (this->parse_ip(buf, len, m_ip_buffer)) {
                // TODO: anything to do here ?
            } else {
                tr_warn("matches none: %.*s", (int)len, buf);
            }
            break;
        }
    }
    return false;
}

void WizFi310::trace_cmd(const char *cmd, ...)
{
    va_list args;
    va_start(args, cmd);
    if (MBED_TRACE_MAX_LEVEL >= TRACE_LEVEL_INFO) {
        char output[256];
        int len = vsnprintf(output, 256, cmd, args);
        tr_info("%s|%s: sending: %.*s", recv_state2str(m_recv_state), action2str((action_t)m_active_action), len, output);
        (void)len;
    }
    va_end(args);
}

void WizFi310::end_action()
{
    m_active_action = ActionNone;
}

// runs on the private event queue
void WizFi310::do_reset()
{
    m_serial.attach(NULL);
    m_attached = false;
    if (m_rst != NC) {
        m_nrst_pin = 0;
        // TODO: we may cause a framing error on the m_serial if we cut a transmition
    }

    core_util_critical_section_enter();
    if (m_rx_event_id != 0) {
        m_event_queue.cancel(m_rx_event_id);
        m_rx_event_id = 0;
    }
    core_util_critical_section_exit();

    m_isr_buf_len = 0;
    m_line_buf_len = 0;
    m_recv_state = Unknown;
    m_on_cmd_end = NULL;
    m_data_to_receive = 0;
    if (m_pending_packet != NULL) {
        delete m_pending_packet;
        m_pending_packet = NULL;
    }
    m_pending_socket = NULL;
    for (uint8_t i = 0; i < WIZFI310_SOCKET_COUNT; i++) {
        m_sockets[i].reset();
    }
    MBED_ASSERT(m_heap_used == 0); // all packet must be freed prior to reset
    m_dhcp = true;
    if (m_rst == NC) {
        tr_warn("Using software reset may give unexpected results due to reception latency.");
    } else {
        // clear
        wait_ms(250);
        m_nrst_pin = 1;
        wait_ms(500);
        // flushes the serial port
        while (m_serial.getc() != -1);
    }

    m_attached = true;
    m_serial.attach(Callback<void()>(this, &WizFi310::serial_isr));

    // this is a factory reset
    send_command("AT+MFDEF=FR\r");

    // TODO: setup a timeout ?
    m_greetings_cbk = Callback<void(const char[8])>(this, &WizFi310::do_echo_off);
}

// runs on the event queue
void WizFi310::do_echo_off(const char fw_rev[8])
{
    m_greetings_cbk = NULL;
    memcpy(m_firmware_rev, fw_rev, 8);
    m_recv_state = Ready;
    send_command("AT+MECHO=0\r");
    m_on_cmd_end = Callback<void(cmd_resp_t)>(this, &WizFi310::do_setup_serial);
}

// runs on the event queue
void WizFi310::do_setup_serial(cmd_resp_t rsp)
{
    if (rsp != CmdRspOk) {
        this->fatal_error("Failed to turn echo off");
        return;
    }

#ifdef DEVICE_SERIAL_FC
    if (m_has_hwfc) {
        send_command("AT+USET=115200,N,8,1,HW\r");
    } else
#endif
    {
        // this shall have no effect as other wise we would be reaching this point.
        // we may in the future want to use a higher speed.
        send_command("AT+USET=115200,N,8,1,N\r");
    }
    // m_on_cmd_end = Callback<void(cmd_resp_t)>(this, &WizFi310::serial_setup_done);
    m_greetings_cbk = Callback<void(const char[8])>(this, &WizFi310::device_ready);
}

/*
void WizFi310::serial_setup_done(cmd_resp_t rsp)
{
    if (rsp != CmdRspOk) {
        // signal end of connect
        this->fatal_error("Failed to setup the serial line");
        return;
    }
    if (m_has_hwfc) {
        tr_debug("enabling flow control");
    }
    m_greetings_cbk = Callback<void(const char[8])>(this, &WizFi310::device_ready);
}
*/

void WizFi310::device_ready(const char fw_rev[8])
{
    (void)fw_rev; // not used here.
    m_serial.set_flow_control(SerialBase::RTSCTS, m_rts, m_cts);
    m_greetings_cbk = NULL;

    if (m_active_action == ActionDoConnect) {
        this->do_set_access_point();
    } else if (m_active_action == ActionDoScan) {
        this->do_scan();
    } else {
        this->fatal_error("Unexpected path to device_ready.");
    }
}

void WizFi310::do_set_access_point()
{
    send_command("AT+WSET=0,%s\r", m_cmd_ctx.connect.ap);
    m_on_cmd_end = Callback<void(cmd_resp_t)>(this, &WizFi310::do_set_password);
}

// runs from the event queue
void WizFi310::do_set_password(cmd_resp_t rsp)
{
    if (rsp != CmdRspOk) {
        tr_error("Failed to set accesspoint name %s: %u", m_cmd_ctx.connect.ap, rsp);
        this->set_connection_status(NSAPI_STATUS_DISCONNECTED);
        this->end_action();
        return;
    }

    if (strcmp(m_cmd_ctx.connect.sec, "OPEN") == 0) {
        send_command("AT+WSEC=0,,12345678\r");
    } else {
        send_command("AT+WSEC=0,,%s\r", m_cmd_ctx.connect.pw);
    }
    m_on_cmd_end = Callback<void(cmd_resp_t)>(this, &WizFi310::do_set_dhcp);
}

// runs from the event queue
void WizFi310::do_set_dhcp(cmd_resp_t rsp)
{
    if (rsp != CmdRspOk) {
        tr_error("Failed to set password %s (%s): %u", m_cmd_ctx.connect.pw, m_cmd_ctx.connect.sec, rsp);
        this->set_connection_status(NSAPI_STATUS_DISCONNECTED);
        this->end_action();
        return;
    }

    if (m_dhcp) {
        send_command("AT+WNET=1\r");
    } else {
        // we need to have a way to set these
        send_command("AT+WNET=0,%s,%s,%s\r", m_ip_buffer, m_netmask_buffer, m_gateway_buffer);
    }
    m_on_cmd_end = Callback<void(cmd_resp_t)>(this, &WizFi310::do_join);
}

// runs from the event queue
void WizFi310::do_join(cmd_resp_t rsp)
{
    if (rsp != CmdRspOk) {
        tr_error("Failed configure dhcp: %s (%s,%s,%s)",
                 m_dhcp ? "enabled" : "disabled", m_ip_buffer, m_netmask_buffer, m_gateway_buffer);
        this->set_connection_status(NSAPI_STATUS_DISCONNECTED);
        this->end_action();
        return;
    }
    send_command("AT+WJOIN\r");
    m_on_cmd_end = Callback<void(cmd_resp_t)>(this, &WizFi310::join_done);
}

// runs from the event queue
void WizFi310::join_done(cmd_resp_t rsp)
{
    if (m_connection_status == NSAPI_STATUS_GLOBAL_UP) {
        this->end_action();
    } else if (m_cmd_ctx.connect.attempt < MBED_CONF_WIZFI310_CONNECT_MAX_ATTEMPT) {
        m_cmd_ctx.connect.attempt += 1;
        this->do_join(CmdRspOk);
    } else {
        this->end_action();
    }
}

void WizFi310::do_scan()
{
    send_command("AT+WSCAN\r");
}

// runs from the event queue
void WizFi310::leave_done(cmd_resp_t rsp)
{
    this->end_action();
}

const char *WizFi310::get_ip_address()
{
    return m_ip_buffer;
}

void WizFi310::sopen_done(cmd_resp_t rsp)
{
    socket_t *s = m_cmd_ctx.sopen.s;

    if (rsp != CmdRspOk) {
        MBED_ASSERT(m_active_action != ActionDoSSend);
        end_action();
        socket_event_data_t data;
        s->notify(EventDisconnected, data);
    }
}

void WizFi310::ssend_done(cmd_resp_t rsp)
{
    socket_event_data_t data;
    socket_t *s = m_cmd_ctx.ssend.s;
    if (rsp == CmdRspErrorInvalidInput) {
        data.data_sent.amount_or_error = NSAPI_ERROR_PARAMETER;
    } else if (rsp != CmdRspOk) {
        data.data_sent.amount_or_error = NSAPI_ERROR_DEVICE_ERROR;
    } else {
        MBED_ASSERT(m_cmd_ctx.ssend.did_send);
        uint32_t sent = m_cmd_ctx.ssend.amount;
        this->end_action();

        data.data_sent.amount_or_error = sent;
    }
    s->notify(EventDataSent, data);
}

void WizFi310::do_sclose(int id)
{
    uint32_t expected = ActionNone;
    socket_t *s = &m_sockets[id];
    tr_debug("::do_close(%d): %s", id, socket_t::status2str(s->status));
    if (s->status == socket_t::StatusDisconnected) {
        return;
    }
    if (!core_util_atomic_cas_u32(&m_active_action, &expected, ActionDoSClose)) {
        m_event_queue.call(this, &WizFi310::do_sclose, id);
        return;
    }
    m_cmd_ctx.sclose.id = id;
    m_cmd_ctx.sclose.done = false;
    send_command("AT+SMGMT=%d\r", id);
    m_on_cmd_end = Callback<void(cmd_resp_t)>(this, &WizFi310::sclose_done);
}

void WizFi310::sclose_done(cmd_resp_t rsp)
{
    int id = m_cmd_ctx.sclose.id;
    if (rsp != CmdRspOk) {
        MBED_ASSERT(m_active_action != ActionDoSSend);
        end_action();
        m_event_queue.call(this, &WizFi310::do_sclose, id);
    } else if (id < 0) {
        MBED_ASSERT(m_active_action != ActionDoSSend);
        end_action();
    } else {
        m_cmd_ctx.sclose.done = true;
    }
}

void WizFi310::socket_t::reset()
{
    this->mutex.lock();
    if (this->status != socket_t::StatusDisconnected) {
        this->status = socket_t::StatusDisconnected;
        socket_event_data_t data;
        this->notify(EventDisconnected, data);
    }
    this->mutex.unlock();
}

// must be called when the mutex is locked
void WizFi310::socket_t::notify(socket_event_t evt, socket_event_data_t &data)
{
    this->mutex.lock();
    if (this->cbk) {
        this->cbk(this->data, evt, data);
    } else if (evt == EventDataReceived) {
        // nobody will take ownership of this packet.
        tr_warning("Receiving %lu bytes on a closed socket.", data.data_received.packet->len());
        delete data.data_received.packet;
    }
    this->mutex.unlock();
}

