// Wake up every 5 mins and send data
#define UpdateTime 5

// Timing
#include <elapsedMillis.h>

// Low Power
#include <avr/sleep.h>
#include <avr/wdt.h>
#include <avr/power.h>
#include <avr/interrupt.h>
#include "LowPower.h"

// Arduino
#include <avr/pgmspace.h>
#include <Arduino.h>

// LoRaWAN
#include "lmic.h"
#include "hal/hal.h"
#include <SPI.h>
bool dataSent = false;

// Device Address
u4_t DevAddr = 0x00000000;

// Network Session Key
unsigned char NwkSkey[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

// Application Session Key
unsigned char AppSkey[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

// LoRaWAN Application identifier (AppEUI)
static const u1_t AppEui[8] PROGMEM = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

// ----------------------------------------------------------------------------
// APPLICATION CALLBACKS
// ----------------------------------------------------------------------------

// provide application router ID (8 bytes, LSBF)
void os_getArtEui (u1_t* buf) {
	memcpy(buf, AppEui, 8);
}

// provide device key (16 bytes)
void os_getDevKey (u1_t* buf) {
	memcpy(buf, NwkSkey, 16);
}


/**
 * LoRa module pin mapping
 */
lmic_pinmap pins = {
  .nss = 10,			// Connected to pin D10
  .rxen = 6, 			// For placeholder only, Do not connected on RFM92/RFM95
  .txen = 8, 			// For placeholder only, Do not connected on RFM92/RFM95
  .rst = 0,  			// Needed on RFM92/RFM95? (probably not)
  .dio = {4, 5, 7},		// Specify pin numbers for DIO0, 1, 2
						// connected to D4, D5, D7
};

/**
 * Callback after a LMIC event
 */
void onEvent (ev_t ev) {
	switch(ev) {
		case EV_TXCOMPLETE:
			dataSent = true;
			//Serial.println(F("EV_TXCOMPLETE"));
			break;
	}
}

void setup() {
	//Serial.begin(115200);
	delay(1000);

	// LMIC init
	os_init();

	// Reset the MAC state. Session and pending data transfers will be discarded.
	LMIC_reset();

	// by joining the network, precomputed session parameters are be provided.
	LMIC_setSession(0x1, DevAddr, (uint8_t*)NwkSkey, (uint8_t*)AppSkey);

	// Enabled data rate adaptation
	LMIC_setAdrMode(1);

	// Disable link check validation
	LMIC_setLinkCheckMode(0);

	// Set data rate and transmit power
	LMIC_setDrTxpow(DR_SF7, 15);
}

void loop() {
	// Reset timer
	elapsedMillis sinceWake = 0;

	// Queue the data packet to be sent
	sendData();

	// Wait for the data to send or timeout
	while (!dataSent && sinceWake < 15000) {
		os_runloop_once();
		delay(1);
	}
	os_runloop_once();

	// Shutdown the radio
	os_radio(RADIO_RST);

	// Go to sleep until next time
	signed long sleep = 60000 * UpdateTime;
	sleep -= sinceWake;
	deepSleep(constrain(sleep, 10000, 60000 * UpdateTime));
}

/**
 * Queue data to be sent by LoRaWAN module
 */
void sendData() {
	// Check if there is not a current TX/RX job running
	if (LMIC.opmode & (1 << 7)) {
		// Something already in the queque
		return;
	}

	// Put together the data to send, add your sensor data here
	char packet[20] = "hello world!";

	// Add to the queque
	dataSent = false;
	uint8_t lmic_packet[20];
	strcpy((char *)lmic_packet, packet);
	LMIC_setTxData2(1, lmic_packet, strlen((char *)lmic_packet), 0);
}

/**
 * Sleep for a given number of seconds
 */
void deepSleep(unsigned long sleepMilliSeconds) {
	while (sleepMilliSeconds >= 8000) { LowPower.powerDown(SLEEP_8S, ADC_OFF, BOD_OFF); sleepMilliSeconds -= 8000; }
	if (sleepMilliSeconds >= 4000)    { LowPower.powerDown(SLEEP_4S, ADC_OFF, BOD_OFF); sleepMilliSeconds -= 4000; }
	if (sleepMilliSeconds >= 2000)    { LowPower.powerDown(SLEEP_2S, ADC_OFF, BOD_OFF); sleepMilliSeconds -= 2000; }
	if (sleepMilliSeconds >= 1000)    { LowPower.powerDown(SLEEP_1S, ADC_OFF, BOD_OFF); sleepMilliSeconds -= 1000; }
	if (sleepMilliSeconds >= 500)     { LowPower.powerDown(SLEEP_500MS, ADC_OFF, BOD_OFF); sleepMilliSeconds -= 500; }
	if (sleepMilliSeconds >= 250)     { LowPower.powerDown(SLEEP_250MS, ADC_OFF, BOD_OFF); sleepMilliSeconds -= 250; }
	if (sleepMilliSeconds >= 125)     { LowPower.powerDown(SLEEP_120MS, ADC_OFF, BOD_OFF); sleepMilliSeconds -= 120; }
	if (sleepMilliSeconds >= 64)      { LowPower.powerDown(SLEEP_60MS, ADC_OFF, BOD_OFF); sleepMilliSeconds -= 60; }
	if (sleepMilliSeconds >= 32)      { LowPower.powerDown(SLEEP_30MS, ADC_OFF, BOD_OFF); sleepMilliSeconds -= 30; }
	if (sleepMilliSeconds >= 16)      { LowPower.powerDown(SLEEP_15MS, ADC_OFF, BOD_OFF); sleepMilliSeconds -= 15; }
}