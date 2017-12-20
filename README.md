# The WizFi310 WiFi driver for mbed-os
The mbed OS driver for the WizFi310 Wi-Fi module

## Testing
The WizFi310 library contains the core network tests taken from mbed OS. To run the tests you will need mbed CLI and mbed OS.

First, setup the the esp8266-driver and mbed-os repositories for testing:
``` bash
# Sets up the WizFi310 for testing
mbed import wizfi310-driver
cd wizfi310-driver
mbed add mbed-os
```

Now you should be able to run the network tests with `mbed test`:
``` bash
# Runs the ESP8266 network tests, requires a wifi access point
mbed test -t <COMPILER HERE> -m <BOARD HERE> -n tests-net* --compile -DMBED_CFG_WIZFI310_SSID=<SSID HERE> -DMBED_CFG_WIZFI310_PASS=<PASS HERE>
mbed test -t <COMPILER HERE> -m <BOARD HERE> -n tests-net* --run --verbose
```

There are a couple other options that can be used during testing:
- MBED_CFG_WIZFI310_SSID - SSID of the wifi access point to connect to
- MBED_CFG_WIZFI310_PASS - Passphrase of the wifi access point to connect to
- MBED_CFG_WIZFI310_TX - TX pin for the WizFi310 serial connection (defaults to D1)
- MBED_CFG_WIZFI310_RX - TX pin for the WizFi310 serial connection (defaults to D0)
- MBED_CFG_WIZFI310_DEBUG - Enabled debug output from the ESP8266

For example, here is how to enabled the debug output from the WizFi310:
``` bash
# Run the ESP8266 network tests with debug output, requires a wifi access point
mbed test -t <COMPILER HERE> -m <BOARD HERE> -n tests-net* --compile -DMBED_CFG_WIZFI310_SSID=<SSID HERE> -DMBED_CFG_WIZFI310_PASS=<PASS HERE> -MBED_CFG_WIZFI310_DEBUG=true
mbed test -t <COMPILER HERE> -m <BOARD HERE> -n tests-net* --run --verbose
```
