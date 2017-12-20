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
#include <string.h>
#include "WizFi310Interface.h"
#include "mbed_debug.h"

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

// WizFi310Interface implementation
WizFi310Interface::WizFi310Interface(PinName tx, PinName rx, bool debug)
    : _wizfi310(tx, rx, debug)
{
    memset(_ids, 0, sizeof(_ids));
    memset(_cbs, 0, sizeof(_cbs));

    _wizfi310.attach(this, &WizFi310Interface::event);
}

int WizFi310Interface::connect(const char *ssid, const char *pass, nsapi_security_t security,
                               uint8_t channel)
{
    if (channel != 0) {
        return NSAPI_ERROR_UNSUPPORTED;
    }

    set_credentials(ssid, pass, security);

    return connect();
}

int WizFi310Interface::connect()
{
    char sec[10];
    int i;

    _wizfi310.setTimeout(WIZFI310_CONNECT_TIMEOUT);

    _wizfi310.startup(0);

    if( !_wizfi310.dhcp(true) )
    {
        return NSAPI_ERROR_DHCP_FAILURE;
    }

    if( ap_sec == NSAPI_SECURITY_NONE && (strlen(sec) > 0) )
    {
        ap_sec = NSAPI_SECURITY_UNKNOWN;
    }

    switch( ap_sec )
    {
        case NSAPI_SECURITY_NONE:
            strncpy(sec,"OPEN",strlen("OPEN")+1);
            break;
        case NSAPI_SECURITY_WEP:
            strncpy(sec,"WEP",strlen("WEP")+1);
            break;
        case NSAPI_SECURITY_WPA:
            strncpy(sec,"WPA",strlen("WPA")+1);
            break;
        case NSAPI_SECURITY_WPA2:
            strncpy(sec,"WPA2",strlen("WPA2")+1);
            break;
        case NSAPI_SECURITY_WPA_WPA2:
            strncpy(sec,"WPAWPA2",strlen("WPAWPA2")+1);
            break;
        default:
            strncpy(sec,"",strlen("")+1);
            break;
    }

    for( i=0; i<WIZFI310_MAX_CONNECT; i++ )
    {
        if( _wizfi310.connect(ap_ssid, ap_pass, sec) ) {
            break;
        }

        _wizfi310.reset();
    }

    if( i > WIZFI310_MAX_CONNECT ){
        return NSAPI_ERROR_NO_CONNECTION;
    }

    if( !_wizfi310.getIPAddress() )
    {
        return NSAPI_ERROR_DHCP_FAILURE;
    }

    return NSAPI_ERROR_OK;
}


int WizFi310Interface::set_credentials(const char *ssid, const char *pass, nsapi_security_t security)
{
    memset(ap_ssid, 0, sizeof(ap_ssid));
    strncpy(ap_ssid, ssid, sizeof(ap_ssid));

    memset(ap_pass, 0, sizeof(ap_pass));
    strncpy(ap_pass, pass, sizeof(ap_pass));

    ap_sec = security;
    return 0;
}


int WizFi310Interface::set_channel(uint8_t channel)
{
}

int WizFi310Interface::disconnect()
{
    _wizfi310.setTimeout(WIZFI310_MISC_TIMEOUT);

    if (!_wizfi310.disconnect())
    {
        return NSAPI_ERROR_DEVICE_ERROR;
    }
    return NSAPI_ERROR_OK;
}

const char *WizFi310Interface::get_ip_address()
{
    return _wizfi310.getIPAddress();
}

const char *WizFi310Interface::get_mac_address()
{
    return _wizfi310.getMACAddress();
}

const char *WizFi310Interface::get_gateway()
{
    return _wizfi310.getGateway();
}

const char *WizFi310Interface::get_netmask()
{
    return _wizfi310.getNetmask();
}

int8_t WizFi310Interface::get_rssi()
{
    return _wizfi310.getRSSI();
}

int WizFi310Interface::scan(WiFiAccessPoint *res, unsigned count)
{
    return _wizfi310.scan(res, count);
}

nsapi_error_t WizFi310Interface::gethostbyname(const char *host,
            SocketAddress *address, nsapi_version_t version)
{
	char host_ip[16];

	if( !_wizfi310.dns_lookup(host,host_ip) ){
		return NSAPI_ERROR_DNS_FAILURE;
	}
	if ( !address->set_ip_address(host_ip) ){
		return NSAPI_ERROR_DNS_FAILURE;
	}

	return NSAPI_ERROR_OK;
}

struct wizfi310_socket {
    int id;
    nsapi_protocol_t proto;
    bool connected;
    SocketAddress addr;
};


int WizFi310Interface::socket_open(void **handle, nsapi_protocol_t proto)
{
	// Look for an unused socket
    int id = -1;

    for (int i=0; i<WIZFI310_SOCKET_COUNT; i++) {
        if (!_ids[i]){
            id = i;
            //_ids[i] = true;
            break;
        }
    }

    if (id == -1){
        return NSAPI_ERROR_NO_SOCKET;
    }

    struct wizfi310_socket *socket = new struct wizfi310_socket;
    if (!socket){
        return NSAPI_ERROR_NO_SOCKET;
    }

    socket->id = id;
    socket->proto = proto;
    socket->connected = false;
    *handle = socket;

    return 0;
}

int WizFi310Interface::socket_close(void *handle)
{
    struct wizfi310_socket *socket = (struct wizfi310_socket *)handle;
    int err = 0;
    _wizfi310.setTimeout(WIZFI310_CLOSE_TIMEOUT);

    if (socket->connected && !_wizfi310.close(socket->id)) {
        err = NSAPI_ERROR_DEVICE_ERROR;
    }

    socket->connected = false;
    _ids[socket->id] = false;
    delete socket;
    return err;
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
    _wizfi310.setTimeout(WIZFI310_OPEN_TIMEOUT);

    const char *proto = (socket->proto == NSAPI_UDP) ? "UCN" : "TCN";
    if (!_wizfi310.open(proto, socket->id, addr.get_ip_address(), addr.get_port())) {
        return NSAPI_ERROR_DEVICE_ERROR;
    }

    socket->connected = true;
    _ids[socket->id] = true;
    return 0;
}
    
int WizFi310Interface::socket_accept(void *server, void **socket, SocketAddress *addr)
{
    return NSAPI_ERROR_UNSUPPORTED;
}
    
int WizFi310Interface::socket_send(void *handle, const void *data, unsigned size)
{
    struct wizfi310_socket *socket = (struct wizfi310_socket *)handle;
    _wizfi310.setTimeout(WIZFI310_SEND_TIMEOUT);

    if (!_wizfi310.send(socket->id, data, size)) {
        return NSAPI_ERROR_DEVICE_ERROR;
    }

    return size;
}
    
int WizFi310Interface::socket_recv(void *handle, void *data, unsigned size)
{
    struct wizfi310_socket *socket = (struct wizfi310_socket *)handle;
    _wizfi310.setTimeout(WIZFI310_RECV_TIMEOUT);

    int32_t recv = _wizfi310.recv(socket->id, data, size);
    if (recv < 0) {
        return NSAPI_ERROR_WOULD_BLOCK;
    }

    return recv;
}
    
int WizFi310Interface::socket_sendto(void *handle, const SocketAddress &addr, const void *data, unsigned size)
{
    struct wizfi310_socket *socket = (struct wizfi310_socket *)handle;

    if (socket->connected && socket->addr != addr) {
        _wizfi310.setTimeout(WIZFI310_MISC_TIMEOUT);
        if (!_wizfi310.close(socket->id)) {
            return NSAPI_ERROR_DEVICE_ERROR;
        }
        socket->connected = false;
    }

    if (!socket->connected) {
        int err = socket_connect(socket, addr);
        if (err < 0 ) {
            return err;
        }
        socket->addr = addr;
    }

    return socket_send(socket, data, size);
}
    
int WizFi310Interface::socket_recvfrom(void *handle, SocketAddress *addr, void *data, unsigned size)
{
    struct wizfi310_socket *socket = (struct wizfi310_socket *)handle;
    int ret = socket_recv(socket, data, size);
    if (ret >= 0 && addr) {
        *addr = socket->addr;
    }

    return ret;
}
    
void WizFi310Interface::socket_attach(void *handle, void (*callback)(void *), void *data)
{
    struct wizfi310_socket *socket = (struct wizfi310_socket *)handle;
    _cbs[socket->id].callback = callback;
    _cbs[socket->id].data = data;
}

void WizFi310Interface::event()
{
    for(int i=0; i<WIZFI310_SOCKET_COUNT; i++){
        if (_cbs[i].callback) {
            _cbs[i].callback(_cbs[i].data);
        }
    }
}
