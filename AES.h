#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<malloc.h>
#include<time.h>
typedef unsigned char word;
#define AES_BLOCK_SIZE 16

void KeySchedule(word * KEY, word * M, word * Roundkey, word * MaskedSbox);
void Precomputing(word* M, word* MaskedSbox);
word xtime(word PlainText);
void AES_encrypt(word* PT, word* CT, word* Roundkey, word* M, word* Maskedsbox);
void MixColumn(word* PlainText);
void ShiftRow(word* PlainText);
void SubByte(word* PT, word* MaskedSbox);
void MixColumn2(word* PlainText);
void inv_ShiftRow(word* PlainText);
void M1_M4_XOR_1nd(word* PT, word* M);
void M1_M4_XOR_2nd(word* PT, word* M);
