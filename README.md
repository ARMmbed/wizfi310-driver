# The WizFi310 WiFi driver for mbed-os
The mbed OS driver for the WizFi310 Wi-Fi module

## Testing
In order to test the driver please download `mbed-os-example-wifi`, update `mbed_app.json` according to your pin setup and run
`mbed test -n 'mbed-os-tests-netsocket-*,mbed-os-tests-network-*' -t <YOUR_TOOLCHAIN> -m detect`
