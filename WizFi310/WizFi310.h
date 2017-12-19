
#ifndef WIZFI310_H_
#define WIZFI310_H_

#include "ATCmdParser.h"

/** WizFi310Interface class.
    This is an interface to a WizFi310Interface radio.
*/
class WizFi310
{
public:
    WizFi310(PinName tx, PinName rx, bool debug=false);

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
    * Receives data from an open socket
    *
    * @param id id to receive from
    * @param data placeholder for returned information
    * @param amount number of bytes to be received
    * @return the number of bytes received
    */
    int32_t recv(int id, void *data, uint32_t amount);

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
    void attach(Callback<void()> func);

    /**
    * Attach a function to call whenever network state has changed
    *
    * @param obj pointer to the object to call the member function on
    * @param method pointer to the member function to call
    */
    template <typename T, typename M>
    void attach(T *obj, M method) {
        attach(Callback<void()>(obj, method));
    }

private:
    UARTSerial _serial;
    ATCmdParser _parser;

    struct packet {
        struct packet *next;
        int id;
        uint32_t len;
        // data follows
    } *_packets, **_packets_end;
    void _packet_handler();
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
};



//#include "WizFi310_conf.h"
//
//#include "mbed.h"
//#include "RawSerial.h"
//#include "Serial.h"
//#include "CBuffer.h"
//#include <ctype.h>
//#include <stdlib.h>
//#include <string>
//#include "WiFiInterface.h"
//
//using namespace std;
//
//#define BUF_SIZE 1600
//
////Debug is disabled by default
//#if 1
//#define WIZ_DBG(x, ...) std::printf("[WizFi310: DBG]" x "\r\n", ##__VA_ARGS__);
//#define WIZ_WARN(x, ...) std::printf("[WizFi310: WARN]" x "\r\n", ##__VA_ARGS__);
//#define WIZ_ERR(x, ...) std::printf("[WizFi310: ERR]" x "\r\n", ##__VA_ARGS__);
//#define WIZ_INFO(x, ...) std::printf("[WizFi310: INFO]" x "\r\n", ##__VA_ARGS__);
//#else
//#define WIZ_DBG(x, ...)
//#define WIZ_WARN(x, ...)
//#define WIZ_ERR(x, ...)
//#define WIZ_INFO(x, ...)
//#endif
//
//
//class WizFi310
//{
//public:
//    
//    enum AntennaMode{
//        PCB = 0,
//        UFL = 1,
//        AUTO = 3,
//    };
//
//    enum WiFiMode {
//        WM_STATION = 0,
//        WM_AP = 1,
//    };
//
//    /** Wi-Fi security
//     */
//    enum Security {
//        // kaizen need to change
//        SEC_AUTO        = 0,
//        SEC_OPEN        = 1,
//        SEC_WEP         = 2,
//        SEC_WPA_TKIP    = 3,
//        SEC_WPA_AES     = 4,
//        SEC_WPA2_AES    = 5,
//        SEC_WPA2_TKIP   = 6,
//        SEC_WPA2_MIXED  = 7,
//    };
//
//    /** TCP/IP protocol
//     */
//    enum Protocol {
//        PROTO_UDP = 0,
//        PROTO_TCP = 1,
//    };
//
//    /** Client/Server
//     */
//    enum Type {
//        TYPE_CLIENT = 0,
//        TYPE_SERVER = 1,
//    };
//
//    enum Response {
//        RES_NULL,
//        RES_MACADDRESS,
//        RES_WJOIN,
//        RES_CONNECT,
//        RES_SSEND,
//        RES_FDNS,
//        RES_SMGMT,
//        RES_WSTATUS,
//        
//    };
//
//    enum Mode {
//        MODE_COMMAND,
//        MODE_CMDRESP,
//        MODE_DATA_RX,
//        MODE_DATA_RXUDP,
//        MODE_DATA_RXUDP_BULK,
//    };
//
//    enum Status {
//        STAT_NONE,
//        STAT_READY,
//        STAT_STANDBY,
//        STAT_WAKEUP,
//        STAT_DEEPSLEEP,
//    };
//
//
//    WizFi310 (PinName tx, PinName rx, PinName cts, PinName rts, PinName reset, PinName alarm = NC, int baud = 115200);
//
//    // --------- WizFi250_at.cpp ---------
//    void clearFlags     ();
//    int  sendCommand    (const char * cmd, Response res = RES_NULL, int timeout = DEFAULT_WAIT_RESP_TIMEOUT, int opt = 2);
//
//    int cmdAT       ();
//    int cmdMECHO    (bool flg);
//    int cmdUSET     (int baud, char *flow);
//    int cmdMMAC     (const char *mac = NULL);
//    int cmdWSET     (WiFiMode mode, const char *ssid, const char *bssid = NULL, int channel = 1);
//    int cmdWANT     (AntennaMode mode);
//    int cmdWNET     (bool is_dhcp);
//    int cmdWSEC     (WiFiMode mode, const char *key, const char *sec = NULL);
//    int cmdWJOIN    ();
//    int cmdWLEAVE   ();
//    int cmdWSTATUS  ();
//    int cmdSCON     ( const char *openType, const char *socketType, int localPort, const char *dataMode = "0");
//    int cmdSCON     ( const char *openType, const char *socketType, const char *remoteIp, int remotePort, int localPort = 0, const char *dataMode = "0");
//    int cmdSSEND    ( const char *data, int cid, int sendSize, const char *remoteIp = NULL, int remotePort = 0, int Timeout = 2000 );
//    int cmdCLOSE    ( int cid );
//    int cmdFDNS     (const char *host);
//    int cmdSMGMT    ( int cid );
//
//
//    static WizFi310 * getInstance() {
//        return _inst;
//    };
//
//
//    // --------- WizFi2550_sock.cpp ---------
//    int getHostByName   (const char * host, char *ip);
//    int open            (Protocol proto, const char *ip, int remotePort, int localPort = 0, void(*func)(int) = NULL);
//    int listen          (Protocol proto, int port, void(*func)(int)=NULL);
//    int close           (int cid);
//    void initCon        (int cid, bool connected);
//    int send            (int cid, const char *buf, int len);
//    int sendto          (int cid, const char *buf, int len, const char *ip, int port);
//    int recv            (int cid, char *buf, int len);
//    int recvfrom        (int cid, char *buf, int len, char *ip, int *port);
//    int readable        (int cid);
//    bool isConnected    (int cid);
//    int accept          (int cid);
//    int getRemote       (int cid, char **ip, int *port);
//        
//
//protected:
//    static WizFi310 * _inst;
//
//    // Serial _wizfi
//    RawSerial _wizfi;
//    
//    int _baud;
//    DigitalIn *_cts;
//    DigitalOut *_rts;
//    int _flow;
//
//    DigitalInOut _reset;
//
//    struct STATE {
//        WiFiMode wm;
//        
//        //daniel
//        //Security sec;
//        nsapi_security_t sec;
//        char ssid[35];
//        char pass[66];
//        char ip[16];
//        char netmask[16];
//        char gateway[16];
//        char nameserver[16];
//        char mac[18];
//        char resolv[16];
//        char name[32];
//        int rssi;
//        bool dhcp;
//        time_t time;
//
//        bool initialized;
//        bool associated;
//        volatile Mode mode;
//        volatile Status status;
//        bool escape;
//        volatile bool ok, failure;
//        volatile Response res;
//        int cid;
//        int n;
//        CircBuffer<char> *buf;
//    } _state;
//
//
//public:
//    struct CONNECTION {
//        Protocol protocol;
//        Type type;
//        bool connected;
//        char ip[16];
//        int port;
//        int send_length;
//        int recv_length;
//        CircBuffer<char> *buf;
//        volatile bool received;
//        volatile int parent;
//        volatile bool accept;
//        void(*func)(int);
//    } _con[8];
//
//    // --------- WizFi310.cpp ---------
//
//    int join(WiFiMode mode);
//    bool isAssociated();
//
//    //int limitedap ();
//    //int dissociate ();
//    /*
//    int disconnect () {
//        return dissociate();
//    }
//    */
//
//    Status getStatus ();
//
//    int setMacAddress   (const char *mac);
//    int getMacAddress   (char *mac);
//    int setAddress      (const char *name = NULL);
//    int setAddress      (const char *ip, const char *netmask, const char *gateway, const char *dns = NULL, const char *name = NULL);
//    int getAddress      (char *ip, char *netmask, char *gateway);
//    int setSsid         (const char *ssid);
//    //daniel
////    int setSec          (Security sec, const char *phrase);
//    int setSec          (nsapi_security_t sec, const char *phrase);
//
//    const char* getIPAddress    (void);
//    const char* getMACAddress   (void);
//
//    // --------- WizFi250_msg.cpp ---------
//    void recvData       ( char c );
//    int  parseMessage   ();
//    void msgOk          (const char *buf);
//    void msgError       (const char *buf);
//    void msgConnect     (const char *buf);
//    void msgDisconnect  (const char *buf);
//    void msgListen      (const char *buf);
//    //daniel
//    void msgMQTTConnect (const char *buf);
//    void msgMQTTDisconnect (const char *buf);
//
//    void resMacAddress  (const char *buf);
//    void resWJOIN       (const char *buf);
//    void resConnect     (const char *buf);
//    void resSSEND       (const char *buf);
//    void resFDNS        (const char *buf);
//    void resSMGMT       (const char *buf);
//    void resWSTATUS     (const char *buf);
//
//
//    // --------- WizFi250_hal.cpp ---------
//    void setReset   (bool flg);
//    void isrUart    ();
//    int  getUart    ();
//    void putUart    (char c);
//    void setRts     (bool flg);
//    int  lockUart   (int ms);
//    void unlockUart ();
//    void initUart   (PinName cts, PinName rts, PinName alarm, int baud);
//
//
//    // --------- WizFi2550_util.cpp ---------
//    int x2i         (char c);
//    int i2x         (int i);
//
//    // --------- WizFi250_ifc.cpp (For NetworkSocketAPI) ---------
//    /**
//    * Startup the WizFi310
//    *
//    * @return true only if WizFi310 was setup correctly
//    */
//    bool startup(void);
//
//    /**
//    * Reset WizFi310
//    *
//    * @return true only if WizFi310 resets successfully
//    */
//    bool reset(void);
//
//    /**
//    * Disconnect WizFi310 from AP
//    *
//    * @return true only if WizFi310 is disconnected successfully
//    */
//    bool disconnect(void);
//
//    /**
//    * Check if WizFi310 is conenected
//    *
//    * @return true only if the chip has an IP address
//    */
//    bool isConnected(void);
//    
//    
//    //daniel for mqtt
//    char rcvd_mqtt_topic[128];
//
//};

#endif /* WIZFI250_H_ */
