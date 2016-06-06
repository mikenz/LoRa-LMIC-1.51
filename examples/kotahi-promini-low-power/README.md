Example sketch to use LoRa-LMIC-1.51 with an Arduino
=====================================================

This sketch wakes up ever 5 minutes, sends "I'm alive" then shuts everyhting
down and goes back to sleep. It's intended as the basis for a low power, battery
operated node.


Requirements
------------

This makes use of some other libraries:
* [elapsedMillis](https://github.com/pfeerick/elapsedMillis/) from https://github.com/pfeerick/elapsedMillis/
* [LowPower](https://github.com/rocketscream/Low-Power) from https://github.com/rocketscream/Low-Power


LoRaWAN Config
--------------

I'm assuming you're using ABP (Activation By Personalisation), this is the
simplist method (from a code point of view) and lowest power option. It also
leaves you the most amount of space left for you to an your own code later.

Edit variables in the with the values for your network
* `DevAddr` Device address
* `NwkSkey` Network Session Key
* `AppSkey` Application Session Key
* `AppEui`  Application identifier (may not be needed)

Edit `src/lmic/config.h`
* Uncomment the appropriate frequency plan
* Uncomment the appropriate radio backend for your module
* Comment out LORAWAN_CLASSB and LORAWAN_OTAA


Connecting Everything
---------------------

This library has been tested with multiple Arduino Pro Minis (ATMega328p) boards.
I only use 868MHz here in New Zealand so have only tested Semtech SX1276 based
modules. Both NiceRF RFM95W and HopeRF Lora1276 modules are known to work with
this library. Lora modules are normally 3.3v only, so ensure your Arduino is also 3.3v!

Arduino | Lora Module
------------ | -------------
3.3v VCC|VCC
GND|GND
4|DIO0
5|DIO1
6|RXEN (Lora1276 only)
7|DIO2
8|TXEN (Lora1276 only)
10|NSS
11|MOSI
12|MISO
13|SCK
no connection|RST

