#include "WizFi310.h"
#include "mbed_trace.h"
#include "greentea_serial.h"
#include <cctype>

#define TRACE_GROUP                     "WZFI"

using namespace mbed;

// =================================================================================================
// Utility function
static void print(char c, char *&out)
{
    if (isprint((int)c)) {
        *out = c;
        out++;
    } else if (c == '\r') {
        *out = '\\';
        out++;
        *out = 'r';
        out++;
    } else if (c == '\n') {
        *out = '\\';
        out++;
        *out = 'n';
        out++;
    } else {
        out += sprintf(out, "\\%02x", c);
    }
}

static bool isolate_token(char *&next, char *&start, uint32_t &len)
{
    start = next;
    char *end = (char *)memchr(start, '/', len);
    bool res = end != NULL;
    if (res) {
        *end = '\0';
        next = end + 1;
        len -= (end - start) + 1;
    }
    return res;
}

// =================================================================================================
// Static members
bool WizFi310::parse_greeting(const char *buf, uint32_t len, char fw_ver[8])
{
    int count = -1;
    sscanf(buf, "WizFi310 Version %8s (WIZnet Co.Ltd)%n", fw_ver, &count);
    return (count == (int)len);
}

bool WizFi310::parse_error(const char *buf, uint32_t len, volatile cmd_resp_t &rsp)
{
    int count = -1;
    char tmp[20] = {0};
    if ((len < 7) || strncmp(buf, "[ERROR", 6) != 0) {
        return false;
    }
    if (buf[6] == ']') {
        rsp = CmdRspError;
        return true;
    }

    sscanf(buf, "[ERROR: %19[^]]]%n", tmp, &count);
    if (count == (int)len) {
        tr_debug("error: %s", tmp);
        // error to cmd_resp_t
        if (strcmp("INVALID INPUT", tmp) == 0) {
            rsp = CmdRspErrorInvalidInput;
        } else if (strcmp("INVALID SCID", tmp) == 0) {
            rsp = CmdRspErrorInvalidScid;
        } else if (strcmp("WiFi Status", tmp) == 0) {
            rsp = CmdRspErrorWifiStatus;
        } else if (strcmp("MODE STATUS", tmp) == 0) {
            rsp = CmdRspErrorModeStatus;
        } else {
            tr_warn("Unkown error type: %s", tmp);
            rsp = CmdRspError;
        }
    }

    return (count == (int)len);
}

bool WizFi310::parse_linkup_ip(const char *buf, uint32_t len, char ip_buffer[16])
{
    int count = -1;
    sscanf(buf, "  IP Addr    : %15[^ ]%n", ip_buffer, &count);
    //tr_debug("count: %u==%lu? ip: %s", count, len, ip_buffer);
    return (count == (int)len);
}

bool WizFi310::parse_linkup_gw(const char *buf, uint32_t len, char ip_buffer[16])
{
    int count = -1;
    sscanf(buf, "  Gateway    : %15[^ ]%n", ip_buffer, &count);
    //tr_debug("count: %u==%lu? ip: %s", count, len, ip_buffer);
    return (count == (int)len);
}

bool WizFi310::parse_status(char *buf, uint32_t len, char ip_buf[16], char gw_buf[16], char mac_buf[18], int32_t &rssi)
{
    // STA/VM8118528/192.168.0.61/192.168.0.1/00:08:DC:52:A0:42//57
    // <mode>/<ssid>/<ip>/<gw>/<mac>/<txpower>/<rssi>
    // sscanf("STA/%*[^/]/%15[^/]/%15[^/]/%17[^/]/%*[^/]/%d", ip_buf, gw_buf, mac_buf, &rssi); // sscanf requires %[^/] to be non-empty
    char *start = NULL, *next = buf, *end;
    if (!isolate_token(next, start, len)) {
        return false;
    }
    // Mode

    if (!isolate_token(next, start, len)) {
        return false;
    }
    // ssid

    if (!isolate_token(next, start, len)) {
        return false;
    }
    // ip
    strncpy(ip_buf, start, 16);

    if (!isolate_token(next, start, len)) {
        return false;
    }
    // gw
    strncpy(gw_buf, start, 16);

    if (!isolate_token(next, start, len)) {
        return false;
    }
    // mac
    strncpy(mac_buf, start, 18);

    if (!isolate_token(next, start, len)) {
        return false;
    }
    // txpower

    start = next;
    // rssi
    rssi = strtol(start, &end, 10);
    return (end - start) == (int)len;
}

bool WizFi310::parse_connect(const char *buf, uint32_t len, int &id)
{
    int count = -1;
    sscanf(buf, "[CONNECT %d]%n", &id, &count);
    return (count == (int)len);
}

bool WizFi310::parse_disconnect(const char *buf, uint32_t len, int &id)
{
    int count = -1;
    sscanf(buf, "[DISCONNECT %d]%n", &id, &count);
    return (count == (int)len);
}

bool WizFi310::parse_send_rdy(const char *buf, uint32_t len, int &id, uint32_t &plen)
{
    int count = -1;
    sscanf(buf, "[%d,,,%lu]%n", &id, &plen, &count);
    return (count == (int)len);
}

bool WizFi310::parse_recv(const char *buf, uint32_t len, int &id, char ip_buf[16], uint16_t &port, uint32_t &plen)
{
    int count = -1;
    if (buf[0] == '{') {
        sscanf(buf, "{%d,%15[^,],%hu,%lu}%n", &id, ip_buf, &port, &plen, &count);
    }

    return (count == (int)len);
}

bool WizFi310::parse_mac(const char *buf, uint32_t len, char mac_buf[18])
{
    int count = -1;
    sscanf(buf, "%*[0-9A-F]:%*[0-9A-F]:%*[0-9A-F]:%*[0-9A-F]:%*[0-9A-F]:%*[0-9A-F]%n", &count);
    if ((count == ((int)len)) && (len < 18)) {
        strcpy(mac_buf, buf);
    }
    return (count == ((int)len)) && (len < 18);
}

bool WizFi310::parse_ip(const char *buf, uint32_t len, char ip_buf[16])
{
    int count = -1;
    sscanf(buf, "%*3d.%*3d.%*3d.%*3d%n", &count);
    if ((count == ((int)len)) && (len < 16)) {
        strcpy(ip_buf, buf);
    }
    return (count == ((int)len)) && (len < 16);
}


bool WizFi310::parse_ap(char *buf, uint32_t len, nsapi_wifi_ap_t *ap)
{
    char *start = NULL, *next = buf, *end;
    if (!isolate_token(next, start, len)) {
        return false;
    }
    // index

    // ssid
    if (!isolate_token(next, start, len)) {
        return false;
    }
    strncpy(ap->ssid, start, 32);

    // bssid
    if (!isolate_token(next, start, len)) {
        return false;
    }
    sscanf(start, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &ap->bssid[0], &ap->bssid[1], &ap->bssid[2], &ap->bssid[3], &ap->bssid[4], &ap->bssid[5]);

    // rssi
    if (!isolate_token(next, start, len)) {
        return false;
    }
    ap->rssi = strtol(start, &end, 10);
    MBED_ASSERT((end + 1) == next);

    // datarate
    if (!isolate_token(next, start, len)) {
        return false;
    }

    // security
    if (!isolate_token(next, start, len)) {
        return false;
    }
    ap->security = str2sec(start);

    // band
    if (!isolate_token(next, start, len)) {
        return false;
    }

    start = next;
    // channel
    ap->channel = strtoul(start, &end, 10);

    bool res = (end - start) == (int)len;
    if (!res) {
        for (char *ptr = buf; ptr < end; ptr++) {
            if (*ptr == 0) {
                *ptr = '/';
            }
        }
    }
    return res;
}

const char *WizFi310::print_buf(const char *ptr, uint32_t len)
{
    static char output[1024] = {0};
    char *optr = output;
    uint32_t i = 0;
    for (; (i < len) && ((optr - output) < 1020); i++) {
        print(ptr[i], optr);
    }
    if (((optr - output) >= 1020) && (i < len)) {
        *(optr - 3) = '.';
        *(optr - 2) = '.';
        *(optr - 1) = '.';
    }
    *(optr) = '\0';
    return output;
}

nsapi_security_t WizFi310::str2sec(const char *str_sec)
{
    if (strcmp(str_sec, "Open") == 0) {
        return NSAPI_SECURITY_NONE;
    } else if (strcmp(str_sec, "WEP") == 0) {
        return NSAPI_SECURITY_WEP;
    } else if (strcmp(str_sec, "WPA") == 0) {
        return NSAPI_SECURITY_WPA;
    } else if (strcmp(str_sec, "WPA2") == 0) {
        return NSAPI_SECURITY_WPA2;
    } else if (strcmp(str_sec, "WPAWPA2") == 0) {
        return NSAPI_SECURITY_WPA_WPA2;
    }

    return NSAPI_SECURITY_UNKNOWN;
}

