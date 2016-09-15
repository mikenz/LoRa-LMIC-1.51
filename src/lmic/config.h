#ifndef _lmic_config_h_
#define _lmic_config_h_

// Chose a frequency plan
#define CFG_kotahi 1
//#define CFG_eu868 1
//#define CFG_us915 1

// Choose a radio backend
//#define CFG_sx1272_radio 1
#define CFG_sx1276_radio 1

// Include Class B beacon/ping support?
//#define LORAWAN_CLASSB 1

// Include support for Over The Air Activation
//#define LORAWAN_OTAA 1

#if defined(__AVR__) || defined(ARDUINO_SAMD_ZERO)
#define US_PER_OSTICK 30		// 50 works for Atmega 328/16MHz with little debug messaging. 30 seems to be working better
#elif defined(ARDUINO_ARCH_ESP8266)
#define US_PER_OSTICK 20		// To be determined
#elif defined(__MKL26Z64__) || defined(__MK20DX128__)
#define US_PER_OSTICK 20		// 35 works for mini-AES, 25 Works with original AES mode
#endif
#define OSTICKS_PER_SEC (1000000 / US_PER_OSTICK)

#endif // _lmic_config_h_
