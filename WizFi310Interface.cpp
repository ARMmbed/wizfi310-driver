/* WizFi310 implementation of NetworkInterfaceAPI
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
  * @file    WizFi310Interface.h
  * @author  Gateway Team
  * @brief   Implementation file of the NetworkStack for the WizFi310 WiFi Device
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

#include <string.h>
#include "WizFi310Interface.h"
#include "mbed_trace.h"

#define TRACE_GROUP "WZ__"

using namespace mbed;
// Various timeouts for different WizFi310 operations
#ifndef WIZFI310_CONNECT_TIMEOUT
#define WIZFI310_CONNECT_TIMEOUT 15000
#endif
#ifndef WIZFI310_SEND_TIMEOUT
#define WIZFI310_SEND_TIMEOUT    500
#endif
#ifndef WIZFI310_RECV_TIMEOUT
#define WIZFI310_RECV_TIMEOUT    0
#endif
#ifndef WIZFI310_MISC_TIMEOUT
#define WIZFI310_MISC_TIMEOUT    500
#endif
#ifndef WIZFI310_OPEN_TIMEOUT
#define WIZFI310_OPEN_TIMEOUT   10000
#endif
#ifndef WIZFI310_CLOSE_TIMEOUT
#define WIZFI310_CLOSE_TIMEOUT   500
#endif

#ifndef WIZFI310_MAX_CONNECT_COUNT
#define WIZFI310_MAX_CONNECT    2
#endif

#ifndef WIZFI310_DELAY_MS
#define WIZFI310_DELAY_MS       300
#endif

// =================================================================================================
// helper functions
static const char *sec2str(nsapi_security_t sec)
{
    switch (sec) {
        case NSAPI_SECURITY_NONE:
            return "OPEN";
        case NSAPI_SECURITY_WEP:
            return "WEP";
        case NSAPI_SECURITY_WPA:
            return "WPA";
        case NSAPI_SECURITY_WPA2:
            return "WPA2";
        case NSAPI_SECURITY_WPA_WPA2:
            return "WPAWPA2";
        default:
            return "";
    }
}

// =================================================================================================
// WizFi310Interface implementation
WizFi310Interface::WizFi310Interface(PinName tx, PinName rx, PinName rts, PinName cts, PinName rst) :
    m_wizfi310(tx, rx, rts, cts, rst),
    m_mutex("WizFi310Interface")
{
    memset(ap_ssid, 0, sizeof(ap_ssid));
    memset(ap_pass, 0, sizeof(ap_pass));
    ap_sec = NSAPI_SECURITY_NONE;
    m_wizfi310.attach(Callback<void(nsapi_connection_status_t)>(this, &WizFi310Interface::link_status_change));
}

void WizFi310Interface::link_status_change(nsapi_connection_status_t status)
{
    if (m_on_status_change) {
        m_on_status_change(NSAPI_EVENT_CONNECTION_STATUS_CHANGE, status);
    }
    m_semphr.release();
}

// =================================================================================================
// WiFi network api

nsapi_error_t WizFi310Interface::connect(
    const char *ssid,
    const char *pass,
    nsapi_security_t security,
    uint8_t channel)
{
    m_mutex.lock();
    nsapi_error_t res = set_channel(channel);
    if (res == NSAPI_ERROR_OK) {
        res = set_credentials(ssid, pass, security);
    }
    if (res == NSAPI_ERROR_OK) {
        res = connect();
    }
    m_mutex.unlock();
    return  res;
}

nsapi_error_t WizFi310Interface::connect()
{
    if (strlen(ap_ssid) == 0) {
        return NSAPI_ERROR_PARAMETER;
    }
    if ((ap_sec != NSAPI_SECURITY_NONE) && ((strlen(ap_pass) == 0) || (strlen(ap_pass) >= 64))) {
        return NSAPI_ERROR_PARAMETER;
    }
    if (m_wizfi310.status() == NSAPI_STATUS_GLOBAL_UP) {
        return NSAPI_ERROR_IS_CONNECTED;
    } else if (m_wizfi310.status() == NSAPI_STATUS_CONNECTING) {
        return NSAPI_ERROR_WOULD_BLOCK;
    }

    nsapi_error_t res = NSAPI_ERROR_OK;

    m_mutex.lock();
    if (!m_wizfi310.dhcp(true)) {
        res = NSAPI_ERROR_DHCP_FAILURE;
    } else {
        if (ap_sec == NSAPI_SECURITY_NONE && (strlen(ap_pass) > 0)) {
            ap_sec = NSAPI_SECURITY_UNKNOWN;
        }

        m_semphr.wait(0);
        while ((res = m_wizfi310.connect(ap_ssid, ap_pass, sec2str(ap_sec))) == NSAPI_ERROR_WOULD_BLOCK) {
            wait_ms(10);
        }
        if (res == NSAPI_ERROR_IN_PROGRESS) {
            do {
                // wait for connect
                m_semphr.wait();
            } while (m_wizfi310.status() == NSAPI_STATUS_CONNECTING);
            res = (m_wizfi310.status() == NSAPI_STATUS_DISCONNECTED) ? NSAPI_ERROR_NO_CONNECTION : NSAPI_ERROR_OK;
        }
    }
    m_mutex.unlock();

    return res;
}

nsapi_error_t WizFi310Interface::set_channel(uint8_t chan)
{
    if (chan != 0) {
        return NSAPI_ERROR_UNSUPPORTED;
    }
    return NSAPI_ERROR_OK;
}

int WizFi310Interface::set_credentials(const char *ssid, const char *pass, nsapi_security_t security)
{
    if ((ssid == NULL) || (strlen(ssid) == 0)) {
        return NSAPI_ERROR_PARAMETER;
    }
    if ((security != NSAPI_SECURITY_NONE) && ((pass == NULL) || (strlen(pass) == 0) || (strlen(pass) >= 64))) {
        return NSAPI_ERROR_PARAMETER;
    }

    m_mutex.lock();
    memset(ap_ssid, 0, sizeof(ap_ssid));
    strncpy(ap_ssid, ssid, sizeof(ap_ssid));

    memset(ap_pass, 0, sizeof(ap_pass));
    if (pass != NULL) {
        strncpy(ap_pass, pass, sizeof(ap_pass));
    }

    ap_sec = security;
    m_mutex.unlock();

    return NSAPI_ERROR_OK;
}

int WizFi310Interface::disconnect()
{
    nsapi_error_t err = NSAPI_ERROR_NO_CONNECTION;

    m_mutex.lock();
    if (m_wizfi310.status() != NSAPI_STATUS_DISCONNECTED) {
        m_semphr.wait(0);
        while ((err = m_wizfi310.disconnect()) == NSAPI_ERROR_WOULD_BLOCK) {
            wait_ms(10);
        }
        if (err == NSAPI_ERROR_IN_PROGRESS) {
            while (m_wizfi310.status() != NSAPI_STATUS_DISCONNECTED) {
                m_semphr.wait();
                err = NSAPI_ERROR_OK;
            }
        }
    }
    m_mutex.unlock();
    return err;
}

nsapi_connection_status_t WizFi310Interface::get_connection_status() const
{
    return m_wizfi310.status();
}

const char *WizFi310Interface::get_ip_address()
{
    return m_wizfi310.get_ip_address();
}

int8_t WizFi310Interface::get_rssi()
{
    return 0;
}

void WizFi310Interface::attach(Callback<void(nsapi_event_t, intptr_t)> status_cb)
{
    m_mutex.lock();
    m_on_status_change = status_cb;
    m_mutex.unlock();
}

nsapi_size_or_error_t WizFi310Interface::scan(WiFiAccessPoint *res, nsapi_size_t count)
{
    m_mutex.lock();
    m_scan_ctx.res = res;
    m_scan_ctx.count = count;
    m_scan_ctx.idx = 0;

    m_semphr.wait(0);
    nsapi_error_t err = m_wizfi310.scan(Callback<void(nsapi_wifi_ap_t *)>(this, &WizFi310Interface::scan_ap));
    if (err == NSAPI_ERROR_IN_PROGRESS) {
        m_semphr.wait();
    }

    uint32_t total = m_scan_ctx.idx;
    if ((count != 0) && (count < total)) {
        total = count;
    }
    m_mutex.unlock();
    return total;
}

void WizFi310Interface::scan_ap(nsapi_wifi_ap_t *ap)
{
    if (ap == NULL) {
        m_semphr.release();
        return;
    }
    if (m_scan_ctx.idx < m_scan_ctx.count) {
        m_scan_ctx.res[m_scan_ctx.idx] = WiFiAccessPoint(*ap);
    }
    m_scan_ctx.idx += 1;
}

// =================================================================================================
// Socket API
nsapi_error_t WizFi310Interface::socket_open(void **handle, nsapi_protocol_t proto)
{
    tr_debug("socket_open(%p, %d)", handle, proto);
    if (handle == NULL) {
        tr_debug("socket_open()=%d,--", NSAPI_ERROR_PARAMETER);
        return NSAPI_ERROR_PARAMETER;
    }

    // Look for an unused socket
    m_mutex.lock();
    // limit the number of active socket to WIZFI310_SOCKET_COUNT
    if (m_socket_count == WIZFI310_SOCKET_COUNT) {
        m_mutex.unlock();
        tr_debug("socket_open()=%d,--", NSAPI_ERROR_NO_SOCKET);
        return NSAPI_ERROR_NO_SOCKET;
    }

    struct wizfi310_socket *socket = new (std::nothrow) struct wizfi310_socket(m_wizfi310, proto);
    if (!socket) {
        m_mutex.unlock();
        tr_debug("socket_open()=%d,--", NSAPI_ERROR_NO_MEMORY);
        return NSAPI_ERROR_NO_MEMORY;
    }
    m_socket_count += 1;
    m_mutex.unlock();

    *handle = socket;
    tr_debug("socket_open()=0,%p", socket);

    return 0;
}

int WizFi310Interface::socket_bind(void *handle, const SocketAddress &address)
{
    return NSAPI_ERROR_UNSUPPORTED;
}

int WizFi310Interface::socket_listen(void *handle, int backlog)
{
    return NSAPI_ERROR_UNSUPPORTED;
}

int WizFi310Interface::socket_connect(void *handle, const SocketAddress &addr)
{
    struct wizfi310_socket *socket = (struct wizfi310_socket *)handle;
    if (addr.get_ip_version() != NSAPI_IPv4) {
        return NSAPI_ERROR_UNSUPPORTED;
    }

    tr_debug("socket_connect(%p, %s:%u)", handle, addr.get_ip_address(), addr.get_port());
    socket->op_mtx.lock();
    nsapi_error_t res = NSAPI_ERROR_DEVICE_ERROR;
    if (socket->id >= 0) {
        if (socket->connected) {
            res = NSAPI_ERROR_IS_CONNECTED;
        } else {
            res = NSAPI_ERROR_ALREADY;
        }
    } else {
        socket->addr = addr;
        const char *proto = (socket->proto == NSAPI_UDP) ? "UCN" : "TCN";
        int id = NSAPI_ERROR_WOULD_BLOCK;
        while (id == NSAPI_ERROR_WOULD_BLOCK) {
            id = m_wizfi310.open(proto, addr.get_ip_address(), addr.get_port(), socket_event, socket);
            if (id == NSAPI_ERROR_WOULD_BLOCK) {
                wait_ms(1000);
            } else if (id < 0) {
                res = id;
            } else {
                socket->id = id;
                res = NSAPI_ERROR_IN_PROGRESS;
            }
        }
    }
    socket->op_mtx.unlock();
    tr_debug("socket_connect(%p,...)=(%d)%d", handle, socket->id, res);
    return res;
}

int WizFi310Interface::socket_accept(void *server, void **socket, SocketAddress *addr)
{
    return NSAPI_ERROR_UNSUPPORTED;
}

int WizFi310Interface::socket_send(void *handle, const void *data, unsigned size)
{
    tr_debug("socket_send(%p, %p, %u)", handle, data, size);
    if (size == 0) {
        return 0;
    }
    struct wizfi310_socket *socket = (struct wizfi310_socket *)handle;
    socket->op_mtx.lock();
    if (!socket->connected) {
        socket->op_mtx.unlock();
        return NSAPI_ERROR_NO_CONNECTION;
    }
    nsapi_error_t res;
    do {
        socket->semphr.wait(0);
        res = m_wizfi310.send(socket->id, data, size);
        if (res == NSAPI_ERROR_WOULD_BLOCK) {
            wait_ms(10);
        }
    } while (res == NSAPI_ERROR_WOULD_BLOCK);
    if (res == NSAPI_ERROR_IN_PROGRESS) {
        socket->semphr.wait();
        res = size;
    }
    socket->op_mtx.unlock();
    tr_debug("socket_send(%p, %p, %u)=%d", handle, data, size, res);
    return res;
}

int WizFi310Interface::socket_recv(void *handle, void *data, unsigned size)
{
    tr_debug("socket_recv(%p, %p, %u)", handle, data, size);
    struct wizfi310_socket *s = (struct wizfi310_socket *)handle;
    int32_t read = NSAPI_ERROR_WOULD_BLOCK;
    Packet *p = NULL;

    s->state_mtx.lock();
    if (s->first != NULL) {
        p = s->first;

        uint32_t plen = p->len();
        read = p->consume((char *)data, size);
        tr_debug("%d: f: %p l: %p; read: %lu/%lu", __LINE__, s->first, s->last, read, plen);
        (void)plen;
        if (p->len() == 0) {
            s->first = p->next();
            if (s->first == NULL) {
                s->last = NULL;
            } else {
                p->set_next(NULL); // detach head from the rest
            }
            delete p;

            // TODO: we need a way to signal the driver that we made some space for further reception
        }
        tr_debug("%d: f: %p l: %p", __LINE__, s->first, s->last);
    } else if (!s->connected) {
        read = 0;
    }
    s->state_mtx.unlock();
    tr_debug("socket_recv(%p, %p, %u)=%ld", s, data, size, read);
    return read;
}

int WizFi310Interface::socket_sendto(void *handle, const SocketAddress &addr, const void *data, unsigned size)
{
    if (addr.get_ip_version() != NSAPI_IPv4) {
        return NSAPI_ERROR_PARAMETER;
    }
    nsapi_error_t res;

    tr_debug("socket_sendto(%p, %s:%hu, %p, %u)", handle, addr.get_ip_address(), (uint16_t)addr.get_port(), data, size);
    struct wizfi310_socket *socket = (struct wizfi310_socket *)handle;
    socket->op_mtx.lock();
    if (socket->connected && socket->addr != addr) {
        socket->close();
    }
    res = socket_connect(socket, addr);
    if ((res == NSAPI_ERROR_IN_PROGRESS) || (res == NSAPI_ERROR_ALREADY) || (res == NSAPI_ERROR_IS_CONNECTED)) {
        if (!socket->connected) {
            socket->semphr.wait();
        }
        if (!socket->connected) {
            res = NSAPI_ERROR_NO_CONNECTION;
        } else {
            res = socket_send(socket, data, size);
        }
    }
    socket->op_mtx.unlock();
    return res;
}
int WizFi310Interface::socket_recvfrom(void *handle, SocketAddress *addr, void *data, unsigned size)
{
    tr_debug("socket_recvfrom(%p, %p, %u)", handle, data, size);
    struct wizfi310_socket *socket = (struct wizfi310_socket *)handle;
    int ret = socket_recv(socket, data, size);
    if (ret >= 0 && addr) {
        *addr = socket->addr;
    }

    return ret;
}

nsapi_error_t WizFi310Interface::socket_close(void *handle)
{
    struct wizfi310_socket *socket = (struct wizfi310_socket *)handle;
    tr_debug("socket_close(%p)", handle);

    m_mutex.lock();
    socket->close();
    m_socket_count -= 1;
    m_mutex.unlock();
    delete socket;

    return NSAPI_ERROR_OK;
}
void WizFi310Interface::socket_attach(void *handle, void (*callback)(void *), void *data)
{
    tr_debug("socket_attach(%p, %p, %p)", handle, callback, data);
    struct wizfi310_socket *socket = (struct wizfi310_socket *)handle;
    socket->state_mtx.lock();
    socket->cbk = callback;
    socket->data = data;
    socket->state_mtx.unlock();
}

void WizFi310Interface::socket_event(void *ctx, WizFi310::socket_event_t type, WizFi310::socket_event_data_t &data)
{
    struct wizfi310_socket *s = (struct wizfi310_socket *)ctx;
    tr_debug("socket_event(%p, %s)", ctx, WizFi310::event2str(type));
    s->state_mtx.lock();
    switch (type) {
        case WizFi310::EventConnected: {
            s->connected = true;
            s->semphr.release();
            break;
        }
        case WizFi310::EventDataReceived: {
            tr_debug("%d: Data received: %p (f:%p l:%p)", __LINE__, data.data_received.packet, s->first, s->last);
            if (s->last == NULL) {
                s->last = data.data_received.packet;
                s->first = s->last;
            } else {
                s->last->set_next(data.data_received.packet);
                s->last = data.data_received.packet;
            }
            tr_debug("%d: f: %p l: %p", __LINE__, s->first, s->last);
            break;
        }
        case WizFi310::EventDataSent: {
            s->semphr.release();
            break;
        }
        case WizFi310::EventDisconnected: {
            s->connected = false;
            s->id = -1;
            // TODO: on recv transfer the packet owner ship to this layer as we may be disconnected before those data are actually read.
            // This would also remove the need of the WizFi310::recv method.
            s->semphr.release();
            break;
        }
        default: {
            // tr_error("Unknown event %d", type);
            break;
        }
    }
    if (s->cbk) {
        s->cbk(s->data);
    }
    s->state_mtx.unlock();
}

void WizFi310Interface::wizfi310_socket::close()
{
    // no lock required here as no other thread shall access this object as it is freed.
    state_mtx.lock();
    int id = this->id;
    this->id = -1;
    state_mtx.unlock();
    if (id >= 0) {
        wifi.close(id);
    }
}

WizFi310Interface::wizfi310_socket::~wizfi310_socket()
{
    close();
    if (first != NULL) {
        delete first;
    }
}

#ifdef MBED_CONF_WIZFI310_PROVIDE_DEFAULT

WiFiInterface *WiFiInterface::get_default_instance()
{
    static WizFi310Interface wizfi;
    return &wizfi;
}

#endif
