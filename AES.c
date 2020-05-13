#include"AES.h"
//original sbox table 입니다.
unsigned char sbox_Table[256] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};
void ShiftRow(word* PlainText) {//AES암호화의 ShiftRows함수입니다.

	word temp = 0x00;

	temp = PlainText[1];
	PlainText[1] = PlainText[5];
	PlainText[5] = PlainText[9];
	PlainText[9] = PlainText[13];
	PlainText[13] = temp;

	temp = PlainText[2];
	PlainText[2] = PlainText[10];
	PlainText[10] = temp;
	temp = PlainText[6];
	PlainText[6] = PlainText[14];
	PlainText[14] = temp;

	temp = PlainText[15];
	PlainText[15] = PlainText[11];
	PlainText[11] = PlainText[7];
	PlainText[7] = PlainText[3];
	PlainText[3] = temp;


	return;
}

void SubByte(word* PT, word* MaskedSbox) {//AES 암호화에서 MaskedSbox를 이용한 SubByte 함수입니다.
	int cnt_i = 0;
	word temp = 0x00;
	for (cnt_i = 0; cnt_i < 16; cnt_i++) {
		temp = PT[cnt_i];
		PT[cnt_i] = MaskedSbox[temp];
	}
	return;

}
void MixColumn(word* PlainText) {//AES 암호화에서 사용되는 Original MixColumn입니다.
	int cnt_j;
	word PlainText2[AES_BLOCK_SIZE] = { 0x00, };
	for (cnt_j = 0; cnt_j < 13; cnt_j += 4) {
		PlainText2[cnt_j] = xtime(PlainText[cnt_j]) ^ xtime(PlainText[cnt_j + 1]) ^ PlainText[cnt_j + 1] ^ PlainText[cnt_j + 2] ^ PlainText[cnt_j + 3];
		PlainText2[cnt_j + 1] = PlainText[cnt_j] ^ xtime(PlainText[cnt_j + 1]) ^ xtime(PlainText[cnt_j + 2]) ^ PlainText[cnt_j + 2] ^ PlainText[cnt_j + 3];
		PlainText2[cnt_j + 2] = PlainText[cnt_j] ^ PlainText[cnt_j + 1] ^ xtime(PlainText[cnt_j + 2]) ^ xtime(PlainText[cnt_j + 3]) ^ PlainText[cnt_j + 3];
		PlainText2[cnt_j + 3] = xtime(PlainText[cnt_j]) ^ PlainText[cnt_j] ^ PlainText[cnt_j + 1] ^ PlainText[cnt_j + 2] ^ xtime(PlainText[cnt_j + 3]);
	}
	for (cnt_j = 0; cnt_j < AES_BLOCK_SIZE; cnt_j++) {
		PlainText[cnt_j] = PlainText2[cnt_j];
	}





	return;
}
void MixColumn2(word* PlainText) {// 본 논문에서 사용하는 1~8라운드 MixColumn입니다. (ShiftRow전에 MixColumn이 실행되기 때문에 대각선으로 MixColumn이 수행됩니다.)
	int cnt_j;
	word PlainText2[AES_BLOCK_SIZE] = { 0x00, };

	PlainText2[0] = xtime(PlainText[0]) ^ xtime(PlainText[5]) ^ PlainText[5] ^ PlainText[10] ^ PlainText[15];
	PlainText2[5] = PlainText[0] ^ xtime(PlainText[5]) ^ xtime(PlainText[10]) ^ PlainText[10] ^ PlainText[15];
	PlainText2[10] = PlainText[0] ^ PlainText[5] ^ xtime(PlainText[10]) ^ xtime(PlainText[15]) ^ PlainText[15];
	PlainText2[15] = xtime(PlainText[0]) ^ PlainText[0] ^ PlainText[5] ^ PlainText[10] ^ xtime(PlainText[15]);

	PlainText2[1] = xtime(PlainText[1]) ^ xtime(PlainText[6]) ^ PlainText[6] ^ PlainText[11] ^ PlainText[12];
	PlainText2[6] = PlainText[1] ^ xtime(PlainText[6]) ^ xtime(PlainText[11]) ^ PlainText[11] ^ PlainText[12];
	PlainText2[11] = PlainText[1] ^ PlainText[6] ^ xtime(PlainText[11]) ^ xtime(PlainText[12]) ^ PlainText[12];
	PlainText2[12] = xtime(PlainText[1]) ^ PlainText[1] ^ PlainText[6] ^ PlainText[11] ^ xtime(PlainText[12]);

	PlainText2[2] = xtime(PlainText[2]) ^ xtime(PlainText[7]) ^ PlainText[7] ^ PlainText[8] ^ PlainText[13];
	PlainText2[7] = PlainText[2] ^ xtime(PlainText[7]) ^ xtime(PlainText[8]) ^ PlainText[8] ^ PlainText[13];
	PlainText2[8] = PlainText[2] ^ PlainText[7] ^ xtime(PlainText[8]) ^ xtime(PlainText[13]) ^ PlainText[13];
	PlainText2[13] = xtime(PlainText[2]) ^ PlainText[2] ^ PlainText[7] ^ PlainText[8] ^ xtime(PlainText[13]);

	PlainText2[3] = xtime(PlainText[3]) ^ xtime(PlainText[4]) ^ PlainText[4] ^ PlainText[9] ^ PlainText[14];
	PlainText2[4] = PlainText[3] ^ xtime(PlainText[4]) ^ xtime(PlainText[9]) ^ PlainText[9] ^ PlainText[14];
	PlainText2[9] = PlainText[3] ^ PlainText[4] ^ xtime(PlainText[9]) ^ xtime(PlainText[14]) ^ PlainText[14];
	PlainText2[14] = xtime(PlainText[3]) ^ PlainText[3] ^ PlainText[4] ^ PlainText[9] ^ xtime(PlainText[14]);


	for (cnt_j = 0; cnt_j < AES_BLOCK_SIZE; cnt_j++) {
		PlainText[cnt_j] = PlainText2[cnt_j];
	}



	return;
}
void inv_ShiftRow(word* PlainText) { //복호화시 사용하는 inv_ShiftRows함수 입니다.

	int i = 0;
	word temp = 0x00;
	temp = PlainText[13];
	PlainText[13] = PlainText[9];
	PlainText[9] = PlainText[5];
	PlainText[5] = PlainText[1];
	PlainText[1] = temp;

	temp = PlainText[10];
	PlainText[10] = PlainText[2];
	PlainText[2] = temp;
	temp = PlainText[14];
	PlainText[14] = PlainText[6];
	PlainText[6] = temp;

	temp = PlainText[3];
	PlainText[3] = PlainText[7];
	PlainText[7] = PlainText[11];
	PlainText[11] = PlainText[15];
	PlainText[15] = temp;
	return;

};
void M1_M4_XOR_2nd(word* PT, word* M) { // M6~M9에는 M1' M2' M3' M4'이 있고 평문에 M1' M2' M3' M4' 마스킹을 적용하기 위한 함수입니다. 
	PT[0] ^= M[6];
	PT[4] ^= M[6];
	PT[8] ^= M[6];
	PT[12] ^= M[6];

	PT[1] ^= M[7];
	PT[5] ^= M[7];
	PT[9] ^= M[7];
	PT[13] ^= M[7];

	PT[2] ^= M[8];
	PT[6] ^= M[8];
	PT[10] ^= M[8];
	PT[14] ^= M[8];

	PT[3] ^= M[9];
	PT[7] ^= M[9];
	PT[11] ^= M[9];
	PT[15] ^= M[9];
	return;
}
void M1_M4_XOR_1nd(word* PT, word* M) { // M2~M5에는 M1, M2 , M3, M4가 있고 평문에 M1, M2, M3, M4 마스킹을 적용하기 위한 함수입니다.
	PT[0] ^= M[2];
	PT[4] ^= M[2];
	PT[8] ^= M[2];
	PT[12] ^= M[2];

	PT[1] ^= M[3];
	PT[5] ^= M[3];
	PT[9] ^= M[3];
	PT[13] ^= M[3];

	PT[2] ^= M[4];
	PT[6] ^= M[4];
	PT[10] ^= M[4];
	PT[14] ^= M[4];

	PT[3] ^= M[5];
	PT[7] ^= M[5];
	PT[11] ^= M[5];
	PT[15] ^= M[5];
	return;
}
void AES_encrypt(word* PT, word* CT, word* Roundkey, word* M, word* Masksbox) { // 본 논문에서 제시하는 Randomizing the Masked를 적용한 AES 암호화 함수입니다.

	word state[16] = { 0x00, };
	word state2[16] = { 0x00, };
	int cnt_i = 0;
	int cnt_j = 0;
	int cnt_k = 0;
	int cnt_x = 0;
	int cnt_v = 0;
	int cnt_a = 0;
	//암호화

	memcpy(state, PT, 16 * sizeof(word));

	//1~8 라운드 암호화
	for (cnt_i = 0; cnt_i < 8; cnt_i++) {
		// M1',M2',M3',M4' 마스킹
		M1_M4_XOR_2nd(state, M);

		//AddRoundkey
		for (cnt_k = 0; cnt_k < AES_BLOCK_SIZE; cnt_k++) {
			state[cnt_k] ^= Roundkey[cnt_x];
			cnt_x++;
		}
		//SubByte
		SubByte(state, Masksbox);

		//M' 마스킹
		for (cnt_j = 0; cnt_j < AES_BLOCK_SIZE; cnt_j++) {
			state[cnt_j] ^= M[1];
		}

		//M1, M2, M3, M4 마스킹
		M1_M4_XOR_1nd(state, M);

		//ShiftRow전 대각선으로 수행되는 MixColumn 함수
		MixColumn2(state);

		//M1' , M2' , M3' , M4' 마스킹
		M1_M4_XOR_2nd(state, M);

		//ShiftRow
		ShiftRow(state);


	}
	//9라운드
	//M1' , M2' , M3' , M4' 마스킹
	M1_M4_XOR_2nd(state, M);

	//AddRoundkey
	for (cnt_i = 0; cnt_i < AES_BLOCK_SIZE; cnt_i++) {
		state[cnt_i] ^= Roundkey[cnt_x];
		cnt_x++;
	}

	//SubByte
	SubByte(state, Masksbox);

	//M' 마스킹
	for (cnt_j = 0; cnt_j < AES_BLOCK_SIZE; cnt_j++) {
		state[cnt_j] ^= M[1];
	}
	//ShiftRow
	ShiftRow(state);

	//M' 마스킹

	M1_M4_XOR_1nd(state, M);


	//Original MixColumn
	MixColumn(state);

	//M1' , M2' , M3' , M4' 마스킹
	M1_M4_XOR_2nd(state, M);


	//10라운드 

		//M1' , M2' , M3' , M4' 마스킹
	M1_M4_XOR_2nd(state, M);

	//AddRoundKey
	for (cnt_i = 0; cnt_i < AES_BLOCK_SIZE; cnt_i++) {
		state[cnt_i] ^= Roundkey[cnt_x];
		cnt_x++;
	}

	//SubByte
	SubByte(state, Masksbox);

	//M' 마스킹
	for (cnt_j = 0; cnt_j < AES_BLOCK_SIZE; cnt_j++) {
		state[cnt_j] ^= M[1];
	}


	//FinalAddRoundKey
	for (cnt_i = 160; cnt_i < 176; cnt_i++) {
		state2[cnt_i - 160] = Roundkey[cnt_i];
	}
	//마지막 라운드키에 inv_Shift 적용
	inv_ShiftRow(state2);

	//M' 마스킹
	for (cnt_j = 0; cnt_j < AES_BLOCK_SIZE; cnt_j++) {
		state[cnt_j] ^= M[1];
	}

	//AddRoundkey
	for (cnt_i = 0; cnt_i < AES_BLOCK_SIZE; cnt_i++) {
		state[cnt_i] ^= state2[cnt_i];

	}

	//ShiftRow
	ShiftRow(state);

	//Finish
	memcpy(CT, state, sizeof(word) * AES_BLOCK_SIZE);

	return;
}

void KeySchedule(word* KEY, word* M, word* Roundkey, word* MaskedSbox) {
	int cnt_i = 0;
	int cnt_j = 6;
	int cnt_k = 0;
	int count = 0;
	int index = 16;
	word state[AES_BLOCK_SIZE] = { 0x00, };
	word state2[AES_BLOCK_SIZE] = { 0x00, };
	word temp = 0x00;
	word temp2 = 0x00;
	word Rcon[10] = { 0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36 };
	//masked  M,M',  M1,M2,M3,M4,  M1',M2',M3',M4' -> 인덱스 0,1, 2,3,4,5 ,6,7,8,9

	//첫 라운드키에는 마스터키가 저장되므로 마스터키를 라운드키에 저장하는 단계입니다.
	for (cnt_i = 0; cnt_i < AES_BLOCK_SIZE; cnt_i++) {
		Roundkey[cnt_i] = KEY[cnt_i];
	}

	memcpy(state2, KEY, sizeof(word) * AES_BLOCK_SIZE);

	//M1' , M2' , M3', M4' / M 마스킹
	for (cnt_i = 0; cnt_i < AES_BLOCK_SIZE; cnt_i++) {
		Roundkey[cnt_i] = (state2[cnt_i] ^ M[0] ^ M[cnt_j]);
		cnt_j++;
		if (cnt_j == 10) {
			cnt_j = 6;
		}
	}


	memcpy(state, Roundkey, sizeof(word) * AES_BLOCK_SIZE);

	cnt_i = 6;

	while (count < 9) {
		//아래의 for문은 본 논문에서 제시된 키 스케쥴 방법의 인덱스 12,13,14,15를 통하여 그 다음 라운드 키 0,1,2,3 인덱스를 업데이트하기위한 소스코드입니다.
		for (cnt_i = 0; cnt_i < 4; cnt_i++) {

			temp = M[cnt_j] ^ state[cnt_i + 12];

			cnt_j++;
			if (cnt_j == 10) {
				cnt_j = 6;
			}
			temp = MaskedSbox[temp];

			if (cnt_i + 12 == 12) {
				state[3] = temp ^ state[3] ^ M[1];
			}
			else if (cnt_i + 12 == 13) {
				temp2 = Rcon[count] ^ temp;
				state[0] = state[0] ^ temp2 ^ M[1];
			}
			else if (cnt_i + 12 == 14) {
				state[1] = temp ^ state[1] ^ M[1];
			}
			else if (cnt_i + 12 == 15) {

				state[2] = temp ^ state[2] ^ M[1];
			}

		}

		//인덱스 4~11은 M이 마스킹 됩니다.
		for (cnt_i = 4; cnt_i < 12; cnt_i++) {
			state[cnt_i] ^= M[0];
		}

		// 그 다음 라운드키에서 인덱스 0,1,2,3을 통하여 인덱스 4~15까지 업데이트 시키는 소스코드입니다.
		state[4] = state[4] ^ state[0] ^ M[6];
		state[5] = state[5] ^ state[1] ^ M[7];
		state[6] = state[6] ^ state[2] ^ M[8];
		state[7] = state[7] ^ state[3] ^ M[9];
		//
		state[8] = state[8] ^ state[4] ^ M[6];
		state[9] = state[9] ^ state[5] ^ M[7];
		state[10] = state[10] ^ state[6] ^ M[8];
		state[11] = state[11] ^ state[7] ^ M[9];
		//
		state[12] = state[12] ^ state[8] ^ M[0] ^ M[6];
		state[13] = state[13] ^ state[9] ^ M[0] ^ M[7];
		state[14] = state[14] ^ state[10] ^ M[0] ^ M[8];
		state[15] = state[15] ^ state[11] ^ M[0] ^ M[9];

		//업데이트 완료가 되면 그게 라운드키가 되기 떄문에 RoundKey변수에 저장시켜줍니다.
		for (cnt_i = 0; cnt_i < 16; cnt_i++) {
			Roundkey[index] = state[cnt_i];
			index++;
		}

		count++;//while문 카운트와 Rcon을 위한 변수
	}


	//마지막 라운드에서는 라운드키 스케쥴이 다름으로 다르게 처리해야합니다.

	//인덱스 12,13,14,15를 통하여 그 다음 라운드키 인덱스 0,1,2,3을 업데이트하는 소스코드입니다.
	for (cnt_i = 0; cnt_i < 4; cnt_i++) {

		temp = M[cnt_j] ^ state[cnt_i + 12];
		cnt_j++;
		if (cnt_j == 10) {
			cnt_j = 6;
		}
		temp = MaskedSbox[temp];

		if (cnt_i + 12 == 12) {
			state[3] = temp ^ state[3];
		}
		else if (cnt_i + 12 == 13) {
			temp2 = Rcon[count] ^ temp;
			state[0] = state[0] ^ temp2;
		}
		else if (cnt_i + 12 == 14) {
			state[1] = temp ^ state[1];
		}
		else if (cnt_i + 12 == 15) {

			state[2] = temp ^ state[2];
		}

	}

	cnt_j = 6;
	// 인덱스 4~7은 그대로 들어가고, 인덱스 8~11은 M1', M2',M3',M4' 마스킹이 적용됩니다.
	for (cnt_i = 8; cnt_i < 12; cnt_i++, cnt_j++) {
		state[cnt_i] ^= M[cnt_j];
	}
	//최종 업데이트를 위한 소스코드입니다.
	state[4] ^= state[0];
	state[5] ^= state[1];
	state[6] ^= state[2];
	state[7] ^= state[3];


	state[8] ^= state[4];
	state[9] ^= state[5];
	state[10] ^= state[6];
	state[11] ^= state[7];

	state[12] = state[8] ^ state[12] ^ M[6];
	state[13] = state[9] ^ state[13] ^ M[7];
	state[14] = state[10] ^ state[14] ^ M[8];
	state[15] = state[11] ^ state[15] ^ M[9];

	state[8] ^= M[0];
	state[9] ^= M[0];
	state[10] ^= M[0];
	state[11] ^= M[0];

	state[0] = state[0] ^ M[0] ^ M[6];
	state[1] = state[1] ^ M[0] ^ M[7];
	state[2] = state[2] ^ M[0] ^ M[8];
	state[3] = state[3] ^ M[0] ^ M[9];

	//마지막 라운드키를 Roundkey 변수에 저장합니다.
	for (cnt_i = 0; cnt_i < 16; cnt_i++) {
		Roundkey[index] = state[cnt_i];
		index++;
	}


	return;
};
word xtime(word PlainText) {
	PlainText = (PlainText << 1) ^ (((PlainText >> 7) & 0x01) * 0x1b);
	return PlainText;
};


void Precomputing(word* M, word* MaskedSbox) {
	int cnt_i = 0;
	word Temp[4] = { 0x00, };
	//Masked Sbox precomputing
	for (cnt_i = 0; cnt_i < 256; cnt_i++) {
		MaskedSbox[cnt_i ^ M[0]] = sbox_Table[cnt_i] ^ M[1];
	}
	// M1' M2' M3' M4' precomputing
	Temp[0] = xtime(M[2]) ^ xtime(M[3]) ^ M[3] ^ M[4] ^ M[5];
	Temp[1] = M[2] ^ xtime(M[3]) ^ xtime(M[4]) ^ M[4] ^ M[5];
	Temp[2] = M[2] ^ M[3] ^ xtime(M[4]) ^ xtime(M[5]) ^ M[5];
	Temp[3] = xtime(M[2]) ^ M[2] ^ M[3] ^ M[4] ^ xtime(M[5]);

	M[6] = Temp[0];
	M[7] = Temp[1];
	M[8] = Temp[2];
	M[9] = Temp[3];
	return;

}
