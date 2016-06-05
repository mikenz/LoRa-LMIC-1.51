/******************************************************************************************
*
* File:        Encrypt_V30.cpp
* Author:      Gerben den Hartog (Ideetron B.V.). 
*
* Ported to the regular Arduino platform running the LMIC-1.5 stack by Maarten Westenberg.
*
* 
* This file is distributed under GPL 3 license
*
******************************************************************************************/
/****************************************************************************************
*
* Created on: 			05-11-2015
* Supported Hardware: ID150119-02 Nexus board with RFM95
*
* Firmware Version 1.0
* First version
*
* Firmware Version 2.0
* Works the same is 1.0 using own AES encryption
*
* Firmware Version 3.0
* Included direction in MIC calculation and encryption
****************************************************************************************/

/*
*****************************************************************************************
* INCLUDE FILES
*****************************************************************************************
*/

#include "oslmic.h"
#include "Encrypt_V30.h"
#include "AES-128_V10.h"

/*
*****************************************************************************************
* INCLUDE GLOBAL VARIABLES
*****************************************************************************************
*/

extern unsigned char NwkSkey[16];
extern unsigned char AppSkey[16];
extern u4_t DevAddr;

// --------------------------------------------------------------------
//
// --------------------------------------------------------------------
void Encrypt_Payload(unsigned char *Data, unsigned char Data_Length, unsigned int Frame_Counter, unsigned char Direction)
{
	unsigned char i = 1;
	unsigned char j;
	unsigned char Number_of_Blocks = 0x00;
	unsigned char Incomplete_Block_Size = 0x00;

	unsigned char Block_A[16];

	//Calculate number of blocks
	Number_of_Blocks = Data_Length / 16;
	Incomplete_Block_Size = Data_Length % 16;
	if(Incomplete_Block_Size != 0)
	{
		Number_of_Blocks++;
	}

	for(i = 1; i <= Number_of_Blocks; i++) {
		Block_A[0] = 0x01;
		Block_A[1] = 0x00;
		Block_A[2] = 0x00;
		Block_A[3] = 0x00;
		Block_A[4] = 0x00;

		Block_A[5] = Direction;

		Block_A[6] = DevAddr;
		Block_A[7] = DevAddr>>8;
		Block_A[8] = DevAddr>>16;
		Block_A[9] = DevAddr>>24;

		Block_A[10] = (Frame_Counter & 0x00FF);
		Block_A[11] = ((Frame_Counter >> 8) & 0x00FF);

		Block_A[12] = 0x00; //Frame counter upper Bytes
		Block_A[13] = 0x00;

		Block_A[14] = 0x00;

		Block_A[15] = i;

		// Calculate S
		AES_Encrypt(Block_A, AppSkey);
		

		//Check for last block
		if(i != Number_of_Blocks)
		{
			for(j = 0; j < 16; j++) {
				*Data = *Data ^ Block_A[j];
				Data++;
			}
		}
		else
		{
			if (Incomplete_Block_Size == 0) {
				Incomplete_Block_Size = 16;
			}
			
			for(j = 0; j < Incomplete_Block_Size; j++) {
				*Data = *Data ^ Block_A[j];
				Data++;
			}
		}
	}
}

// --------------------------------------------------------------------
//
// --------------------------------------------------------------------
void Calculate_MIC(unsigned char *Data, unsigned char *Final_MIC, unsigned char Data_Length, unsigned int Frame_Counter, unsigned char Direction)
{
	unsigned char i;
	unsigned char Block_B[16] = {
		0x49, 0x00, 0x00, 0x00, 0x00,   // 0-4
		Direction,   					//  5
		(unsigned char)DevAddr,     	//  6
		(unsigned char)(DevAddr>>8),  	//  7
		(unsigned char)(DevAddr>>16), 	//  8
		(unsigned char)(DevAddr>>24), 	//  9
		(unsigned char)(Frame_Counter & 0x00FF), 		// 10
		(unsigned char)((Frame_Counter >> 8) & 0x00FF), // 11
		0x00, 							// 12 Frame counter upper bytes
		0x00,							// 13
		0x00,							// 14
		Data_Length						// 15
	};
	unsigned char Key_K1[16] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	unsigned char Key_K2[16] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	unsigned char Old_Data[16] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	unsigned char New_Data[16] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	unsigned char Block_Counter = 0x01;

	//Calculate number of Blocks and blocksize of last block
	unsigned char Number_of_Blocks = Data_Length / 16;
	unsigned char Incomplete_Block_Size = Data_Length % 16;
	if (Incomplete_Block_Size != 0) {
		Number_of_Blocks++;
	}

	Generate_Keys(Key_K1, Key_K2);

	// Preform Calculation on Block B0

	// Perform AES encryption
	AES_Encrypt(Block_B,NwkSkey);

	// Copy Block_B to Old_Data
	CopyArray(Block_B, Old_Data);

	// Preform full calculating until n-1 messsage blocks
	while(Block_Counter < Number_of_Blocks) {
		// Copy data into array
		for(i = 0; i < 16; i++) {
			New_Data[i] = *Data;
			Data++;
		}

		//Preform XOR with old data
		XOR(New_Data, Old_Data);

		//Preform AES encryption
		AES_Encrypt(New_Data, NwkSkey);

		// Copy from New_Data to Old_Data
		CopyArray(New_Data, Old_Data);

		//Raise Block counter
		Block_Counter++;
	}

	//Perform calculation on last block
	//Check if Datalength is a multiple of 16
	if(Incomplete_Block_Size == 0) {
		//Copy last data into array
		for(i = 0; i < 16; i++) {
			New_Data[i] = *Data;
			Data++;
		}

		//Preform XOR with Key 1
		XOR(New_Data, Key_K1);

		//Preform XOR with old data
		XOR(New_Data, Old_Data);

		//Preform last AES routine
		AES_Encrypt(New_Data, NwkSkey);
	} else {
		//Copy the remaining data and fill the rest
		for(i =  0; i < 16; i++) {
			if (i < Incomplete_Block_Size) {
				New_Data[i] = *Data;
				Data++;
			} else if (i == Incomplete_Block_Size) {
				New_Data[i] = 0x80;
			} else if (i > Incomplete_Block_Size) {
				New_Data[i] = 0x00;
			}
		}

		//Preform XOR with Key 2
		XOR(New_Data, Key_K2);

		//Preform XOR with Old data
		XOR(New_Data, Old_Data);

		//Preform last AES routine
		AES_Encrypt(New_Data, NwkSkey);
	}

	Final_MIC[0] = New_Data[0];
	Final_MIC[1] = New_Data[1];
	Final_MIC[2] = New_Data[2];
	Final_MIC[3] = New_Data[3];
}

// --------------------------------------------------------------------
//
// --------------------------------------------------------------------
void Generate_Keys(unsigned char *K1, unsigned char *K2)
{
	unsigned char MSB_Key;

	//Encrypt the zeros in K1 with the NwkSkey
	AES_Encrypt(K1, NwkSkey);

	// Create K1
	// Check if MSB is 1
	MSB_Key = ((K1[0] & 0x80) == 0x80) ? 1 : 0;

	// Shift K1 one bit left
	Shift_Left(K1);

	// if MSB was 1
	if (MSB_Key == 1) {
		K1[15] = K1[15] ^ 0x87;
	}

	// Copy K1 to K2
	CopyArray(K1, K2);

	// Check if MSB is 1
	MSB_Key = ((K2[0] & 0x80) == 0x80) ? 1 : 0;

	// Shift K2 one bit left
	Shift_Left(K2);

	// Check if MSB was 1
	if (MSB_Key == 1) {
		K2[15] = K2[15] ^ 0x87;
	}
}

// --------------------------------------------------------------------
// Shift all the bits lefts by one, overflowing from one byte to the next
// --------------------------------------------------------------------
void Shift_Left(unsigned char *Data)
{
	unsigned char i;
	for(i = 0; i < 15; i++) {
		// Shift one left and add overflow from the next byte
		Data[i] = (Data[i] << 1) + (((Data[i + 1] & 0x80) == 0x80) ? 1 : 0);	
	}
	
	// 16th round without overflow
	Data[15] = (Data[15] << 1);
}

// --------------------------------------------------------------------
// XOR two arrays
// --------------------------------------------------------------------
void XOR(unsigned char *New_Data, unsigned char *Old_Data)
{
	unsigned char i;
	for(i = 0; i < 16; i++) {
		New_Data[i] = New_Data[i] ^ Old_Data[i];
	}
}

