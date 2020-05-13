#include"AES.h"

int main() {
	//본 폴더에 제시된 테스트 벡터를 사용하여 검증하였습니다.
	word KEY[16] = { 0x2b,0x7e ,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c };
	word M[10] = { 0x10,0x20,0x30,0x40,0x50,0x60,0,0,0,0 };
	word Masksbox[256] = { 0x00, };
	word PT[AES_BLOCK_SIZE] = { 0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34 };
	int cnt_i = 0;
	word RoundKey[176] = { 0x00, };
	word CT[16] = { 0x00, };

	srand(time(NULL));
	//평문 출력
	printf("PT : ");
	for (cnt_i = 0; cnt_i < AES_BLOCK_SIZE; cnt_i++) {
		printf("%X ", PT[cnt_i]);
	}printf("\n");
	//키 출력
	printf("KEY : ");
	for (cnt_i = 0; cnt_i < AES_BLOCK_SIZE; cnt_i++) {
		printf("%X ", KEY[cnt_i]);
	}printf("\n\n");

	//랜덤한 M[0],M[1],M[2],M[3],M[4],M[5] 선택
	M[0] = rand() % 255;
	M[1] = rand() % 255;
	M[2] = rand() % 255;
	M[3] = rand() % 255;
	M[4] = rand() % 255;
	M[5] = rand() % 255;
	printf("Random M[0]=%x M[1]=%x, M[2]=%x, M[3]=%x, M[4]=%x, M[5]=%x\n\n", M[0], M[1], M[2], M[3], M[4], M[5]);

	//M[0], M[1]을 통해 Masksbox 사전 계산 및 M1,M2,M3,M4를 통해 M1' M2' M3' M4'을 사전 계산
	Precomputing(M, Masksbox);
	//마스터 키를 본 논문에서 제시된 방법으로 라운드키 생성
	KeySchedule(KEY, M, RoundKey, Masksbox);
	printf("=====encrypt=====\n");
	//Randomizing the Masked 를 적용하여 AES 암호화
	AES_encrypt(PT, CT, RoundKey, M, Masksbox);

	//암호문 출력
	printf("CT : ");
	for (cnt_i = 0; cnt_i < AES_BLOCK_SIZE; cnt_i++) {
		printf("%X ", CT[cnt_i]);
	}
	return 0;
}
