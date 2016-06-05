#ifndef _lmic_config_h_
#define _lmic_config_h_

// Chose a frequency plan
#define CFG_eu868 1
//#define CFG_us915 1

// Choose a radio backend
//#define CFG_sx1272_radio 1
#define CFG_sx1276_radio 1

// Include Class B beacon/ping support?
//#define LORAWAN_CLASSB 1

// Include support for Over The Air Activation
//#define LORAWAN_OTAA 1

// 50 μs per tick
#define US_PER_OSTICK 50
#define OSTICKS_PER_SEC (1000000 / US_PER_OSTICK)

#endif // _lmic_config_h_
