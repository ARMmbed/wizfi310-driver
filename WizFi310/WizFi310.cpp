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

#include "WizFi310.h"
#define WIZFI310_DEFAULT_BAUD_RATE      115200

#define AT_CMD_PARSER_DEFAULT_TIMEOUT     500
#define AT_CMD_PARSER_INIT_TIMEOUT       1000
#define AT_CMD_PARSER_RECV_TIMEOUT      20000

using namespace mbed;
WizFi310::WizFi310(PinName tx, PinName rx, PinName rts, PinName cts, bool debug)
    : _serial(tx, rx, WIZFI310_DEFAULT_BAUD_RATE),
      _rts(rts), _cts(cts),
      _parser(&_serial),
      _packets(0),
      _packets_end(&_packets)
{
    _serial.set_baud( WIZFI310_DEFAULT_BAUD_RATE );
    _parser.debug_on(debug);
    _parser.set_delimiter("\r\n");

    for(int i=0; i<10; i++)
    {
        if( _parser.send("AT") && _parser.recv("[OK]") )
        {
            _parser.send("AT+MECHO=0");
            _parser.recv("[OK]");
            _parser.send("AT+MPROF=S");
            _parser.recv("[OK]");
            _parser.send("AT+MRESET");
            _parser.recv("[OK]");
            break;
        }
    }

    _parser.recv("WizFi310 Version %s (WIZnet Co.Ltd)", _firmware_version);
}

const char* WizFi310::get_firmware_version()
{
    if( strlen(_firmware_version) != 0 )
    {
        return _firmware_version;
    }

    _parser.send("AT+MINFO");
    if( _parser.recv("%s/WizFi310 Rev", _firmware_version) )
    {
        return _firmware_version;
    }

    return 0;
}

bool WizFi310::startup(int mode)
{	
    if( mode != 0 && mode != 1 )
    {
        return false;
    }
    _op_mode = mode;

	_parser.oob("{", callback(this, &WizFi310::_packet_handler));
	
#if !DEVICE_SERIAL_FC
    if( _parser.send("AT+USET=%d,N,8,1,N",WIZFI310_DEFAULT_BAUD_RATE)
        && _parser.recv("[OK]")
        && _parser.recv("WizFi310 Version %s (WIZnet Co.Ltd)", _firmware_version) )
    {
        //debug_if(_dbg_on, "error disabling HW flow control\r\n");
        return false;
    }
	_serial.set_flow_control(SerialBase::Disabled);
#else
    if( (_rts != NC) && (_cts != NC) )
    {
        if( _parser.send("AT+USET=%d,N,8,1,HW",WIZFI310_DEFAULT_BAUD_RATE)
            && _parser.recv("[OK]")
            && _parser.recv("WizFi310 Version %s (WIZnet Co.Ltd)", _firmware_version) )
        {
            //debug_if(_dbg_on, "error enabling HW flow control\r\n");
            return false;
        }
		_serial.set_flow_control(SerialBase::RTSCTS, _rts, _cts);
    }
    else
    {
        if( _parser.send("AT+USET=%d,N,8,1,N",WIZFI310_DEFAULT_BAUD_RATE)
            && _parser.recv("[OK]")
            && _parser.recv("WizFi310 Version %s (WIZnet Co.Ltd)", _firmware_version) )
        {
            //debug_if(_dbg_on, "error disabling HW flow control\r\n");
            return false;
        }
		_serial.set_flow_control(SerialBase::Disabled);
    }
#endif //DEVICE_SERIAL_FC

    return true;
}

bool WizFi310::reset(void)
{
    for (int i=0; i<2; i++)
    {
        if(_parser.send("AT+MRESET")
           && _parser.recv("[OK]"))
        {
            return true;
        }
    }

    return false;
}

bool WizFi310::dhcp(bool enabled)
{
    _dhcp = enabled;
    return _dhcp;
}

bool WizFi310::connect(const char *ap, const char *passPhrase, const char *sec)
{
   if ( !(_parser.send("AT+WSET=0,%s", ap) && _parser.recv("[OK]")) )
   {
       return false;
   }

   //if ( !(_parser.send("AT+WSEC=0,%s,%s", sec, passPhrase) && _parser.recv("[OK]")) )
   if ( !(_parser.send("AT+WSEC=0,,%s", passPhrase) && _parser.recv("[OK]")) )
   {
       return false;
   }

   if (_dhcp)
   {
       if ( !(_parser.send("AT+WNET=1") && _parser.recv("[OK]")) )
       {
           return false;
       }
   }
   else
   {
       if ( !(_parser.send("AT+WNET=0,%s,%s,%s",_ip_buffer,_netmask_buffer,_gateway_buffer)
             && _parser.recv("[OK]")) )
       {
           return false;
       }
   }

   if ( !(_parser.send("AT+WJOIN") && _parser.recv("[Link-Up Event]")
       && _parser.recv("  IP Addr    : %[^\n]\r\n",_ip_buffer)
       && _parser.recv("  Gateway    : %[^\n]\r\n",_gateway_buffer)
       && _parser.recv("[OK]")) )
   {
        return false;
   }

   return true;
}

bool WizFi310::disconnect(void)
{
    return _parser.send("AT+WLEAVE") && _parser.recv("[OK]");
}

const char *WizFi310::getIPAddress(void)
{
    if (!(_parser.send("AT+WSTATUS") && _parser.recv("IF/SSID/IP-Addr/Gateway/MAC/TxPower(dBm)/RSSI(-dBm)")
         && _parser.recv("%*[^/]/%*[^/]/%15[^/]/",_ip_buffer)
         && _parser.recv("[OK]")) )
    {
        return 0;
    }

    return _ip_buffer;
}

const char *WizFi310::getMACAddress(void)
{
    if (!(_parser.send("AT+MMAC=?")
        && _parser.recv("%[^\n]\r\n",_mac_buffer)
        && _parser.recv("[OK]"))) {
        return 0;
    }

    return _mac_buffer;
}

const char *WizFi310::getGateway()
{
   return _gateway_buffer; 
}

const char *WizFi310::getNetmask()
{
    return _netmask_buffer;
}

int8_t WizFi310::getRSSI()
{
    char rssi[3];

    if (!(_parser.send("AT+WSTATUS") && _parser.recv("IF/SSID/IP-Addr/Gateway/MAC/TxPower(dBm)/RSSI(-dBm)")
         //&& _parser.recv("%*[^/]/%*[^/]/%*[^/]/%*[^/]/%*[^/]/%*[^/]/%[^\n]\r\n",&rssi)
         && _parser.recv("%*[^/]/%*[^/]/%*[^/]/%*[^/]/%*[^/]//%[^\n]\r\n",rssi)
         && _parser.recv("[OK]")) )
    {
        return 0;
    }

    return atoi(rssi);
}

bool WizFi310::isConnected(void)
{
    return getIPAddress() != 0;
}

int WizFi310::scan(WiFiAccessPoint *res, unsigned limit)
{
    unsigned int cnt = 0;
    nsapi_wifi_ap_t ap;

    // Scan Time out : 50ms
    if (!(_parser.send("AT+WSCAN=,,,50")
        && _parser.recv("Index/SSID/BSSID/RSSI(-dBm)/MaxDataRate(Mbps)/Security/RadioBand(GHz)/Channel")))
    {
        return NSAPI_ERROR_DEVICE_ERROR;
    }
    
    while (recv_ap(&ap)) {
        if (cnt < limit)
        {
            res[cnt] = WiFiAccessPoint(ap);
        }
        cnt++;
        if (limit != 0 && cnt >= limit)
        {
            break;
        }
    }

    return cnt;
}

bool WizFi310::open(const char *type, int id, const char* addr, int port)
{
    int created_sock_id;

    //IDs only 0-7
    if(id > 7) {
        return false;
    }

    if( !(_parser.send("AT+SCON=O,%s,%s,%d,,0",type,addr,port) && _parser.recv("[OK]")
    		&& _parser.recv("[CONNECT %d]",&created_sock_id))) {
    	return false;
    }

    if( created_sock_id != id ) {
       close(created_sock_id); 
       return false;
    }

    return true;
}

bool WizFi310::dns_lookup(const char* name, char* ip)
{
	return (_parser.send("AT+FDNS=%s,5000", name) && _parser.recv("%[^\n]\r\n",ip) && _parser.recv("[OK]"));
}

bool WizFi310::send(int id, const void *data, uint32_t amount)
{
    char str_result[20];

    if(id > 8) {
        return false;
    }

    sprintf(str_result,"[%d,,,%d]",id,(int)amount);
    
    // Using _parser.printf because MCU can't send CR LF
    if( _parser.printf("AT+SSEND=%d,,,%d\r",id, (int)amount)
     && _parser.recv(str_result)
     && _parser.write((char*)data, (int)amount) >= 0
     && _parser.recv("[OK]") ){
        return true;
    }

    return false;
}

void WizFi310::_packet_handler()
{
    int id;
    char ip_addr[16];
    int port;
    uint32_t amount;

    // parse out the packet
    _parser.set_timeout(AT_CMD_PARSER_RECV_TIMEOUT);
    if (!_parser.recv("%d,%[^,],%d,%d}",&id, ip_addr,&port, &amount) ) {
        setTimeout(_timeout_ms);
        return;
    }

	struct packet *packet = new struct packet(id, amount);
    if (!packet) {
        return;
    }

    if (!(_parser.read((char*)packet->data, amount))) {
		delete(packet);
        setTimeout(_timeout_ms);
        return;
    }
    setTimeout(_timeout_ms);

    *_packets_end = packet;
    _packets_end = &packet->next;
}

int32_t WizFi310::recv_tcp(int id, void *data, uint32_t amount)
{
    while(_parser.process_oob()) {
    }

    for (struct packet **p = &_packets; *p; p = &(*p)->next) {
        if ((*p)->id == id) {
            struct packet *q = *p;

            if (q->len <= amount) {
                memcpy(data,q->data, q->len);

                if (_packets_end == &(*p)->next) {
                    _packets_end = p;
                }
                *p = (*p)->next;

                uint32_t len = q->len;
                delete(q);
                return len;
            } else { // return only partial packet
                memcpy(data, q->data, amount);

                q->len -= amount;
                memmove(q->data, (uint8_t*)(q->data) + amount, q->len);
                return amount;
            }
        }
    }

    return NSAPI_ERROR_WOULD_BLOCK;
}

int32_t WizFi310::recv_udp(int id, void *data, uint32_t amount)
{
    // Poll for inbound packets
    while (_parser.process_oob()) {
    }

    // check if any packets are ready for us
    for (struct packet **p = &_packets; *p; p = &(*p)->next) {
        if ((*p)->id == id) {
            struct packet *q = *p;

            // Return and remove packet (truncated if necessary)
            uint32_t len = q->len < amount ? q->len : amount;
            memcpy(data, q->data, len);

            if (_packets_end == &(*p)->next) {
                _packets_end = p;
            }
            *p = (*p)->next;

            delete(q);
            return len;
        }
    }

    return NSAPI_ERROR_WOULD_BLOCK;
}

bool WizFi310::close(int id)
{
    char sock_event_msg[15];

    if(id > 7) {
        return false;
    }

    if (_parser.send("AT+SMGMT=%d", id) && _parser.recv(sock_event_msg) && _parser.recv("[OK]") )
    {
        return true;
    }

    return false;
}

void WizFi310::setTimeout(uint32_t timeout_ms)
{
    _parser.set_timeout(timeout_ms);
    _timeout_ms = timeout_ms;
}

bool WizFi310::readable()
{
    return _serial.FileHandle::readable();
}

bool WizFi310::writeable()
{
    return _serial.FileHandle::writable();
}

void WizFi310::attach(Callback<void()> func)
{
    _serial.sigio(func);
}

bool WizFi310::recv_ap(nsapi_wifi_ap_t *ap)
{
    char scan_result[100];
    char sec[10];
    char bssid[32];
    char* idx_ptr;
    char* bssid_ptr;
    
    _parser.recv("%s\r\n",scan_result);
    if( strcmp(scan_result,"[OK]") == 0 )
    {
        return false;
    }

    idx_ptr = strtok((char*)scan_result, "/");      // index

    idx_ptr = strtok( NULL, "/" );                  // ssid
    strncpy(ap->ssid,idx_ptr,strlen(idx_ptr));
    ap->ssid[strlen(idx_ptr)] = '\0';

    idx_ptr = strtok( NULL, "/" );                  // bssid
    strncpy(bssid,idx_ptr,strlen(idx_ptr));
    bssid[strlen(idx_ptr)] = '\0';
    
    idx_ptr = strtok( NULL, "/" );                  // RSSI
    ap->rssi = atoi(idx_ptr);

    //idx_ptr = strtok( NULL, "/" );                  // DataRate
    
    idx_ptr = strtok( NULL, "/" );                  // Security
    strncpy(sec,idx_ptr,strlen(idx_ptr));
    sec[strlen(idx_ptr)] = '\0';
    ap->security = str2sec(sec);

    idx_ptr = strtok( NULL, "/" );                  // RadioBand

    idx_ptr = strtok( NULL, "/" );                  // Channel
    ap->channel = atoi(idx_ptr);

    // Set BSSID
    bssid_ptr = strtok( (char*)bssid, ":");
    ap->bssid[0] = hex_str_to_int(bssid_ptr);

    for(int i=1; i<6; i++)
    {
        bssid_ptr = strtok( NULL, ":");
        ap->bssid[i] = hex_str_to_int(bssid_ptr);
    }

    return true; 
}

nsapi_security_t WizFi310::str2sec(const char *str_sec)
{
    if( strcmp(str_sec,"Open") == 0 )
    {
        return NSAPI_SECURITY_NONE;
    }
    else if( strcmp(str_sec,"WEP") == 0 )
    {
        return NSAPI_SECURITY_WEP;
    }
    else if( strcmp(str_sec,"WPA") == 0 )
    {
        return NSAPI_SECURITY_WPA;
    }
    else if( strcmp(str_sec,"WPA2") == 0 )
    {
        return NSAPI_SECURITY_WPA2;
    }
    else if( strcmp(str_sec,"WPAWPA2") == 0 )
    {
        return NSAPI_SECURITY_WPA_WPA2;
    }

    return NSAPI_SECURITY_UNKNOWN;
}

int WizFi310::hex_str_to_int(const char* hex_str)
{
    int n = 0;
    uint32_t value = 0;
    int shift = 7;
    while (hex_str[n] != '\0' && n < 8)
    {
        if ( hex_str[n] > 0x21 && hex_str[n] < 0x40 )
        {
            value |= (hex_str[n] & 0x0f) << (shift << 2);
        }
        else if ( (hex_str[n] >= 'a' && hex_str[n] <= 'f') || (hex_str[n] >= 'A' && hex_str[n] <= 'F') )
        {
            value |= ((hex_str[n] & 0x0f) + 9) << (shift << 2);
        }
        else
        {
            break;
        }
        n++;
        shift--;
    }

    return (value >> ((shift + 1) << 2));
}

