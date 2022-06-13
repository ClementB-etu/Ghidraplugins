#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
/* WARNING: Function: __x86.get_pc_thunk.ax replaced with injection: get_pc_thunk_ax */char * lVwKorZWxHNQwb(char *param_1,int param_2,int param_3,int param_4){for (; 0 < param_4; param_4 = param_4 + -1) {*param_1 = *(char *)(param_2 + param_3);param_1 = param_1 + 1;param_2 = param_2 + 1;}*param_1 = 0;return param_1;}/* WARNING: Function: __x86.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx */int TqbLimi(char * param_1){int iVar1;int iVar2;uint uVar3;int iVar4;int in_GS_OFFSET;int local_3c;int local_38;int local_34;char local_14 [4];int local_10;local_10 = *(int *)(in_GS_OFFSET + 0x14);iVar1 = strlen(param_1);if (iVar1 < 0) {iVar1 = iVar1 + 3;}iVar2 = calloc((iVar1 >> 2) + 1,1);if (iVar2 == 0) {iVar2 = 0;}else {local_3c = 0;for (local_34 = 0; local_34 < iVar1 >> 2; local_34 = local_34 + 1) {lVwKorZWxHNQwb(local_14,param_1,local_3c,4);local_10 = asmvol(uVar3);uVar3 = strtol(local_14,0,0x10);iVar4 = (int)(uVar3 & 0xffff0000 | (uint)(unsigned char)((char)uVar3 + (char)(uVar3 >> 8) * '\n')) %100;if (iVar4 < 10) {local_38 = iVar4 + 0x30;}else if ((iVar4 < 10) || (0x23 < iVar4)) {if ((iVar4 < 0x24) || (0x3d < iVar4)) {if ((iVar4 < 0x3e) || (0x4c < iVar4)) {if ((iVar4 < 0x4d) || (0x53 < iVar4)) {if ((iVar4 < 0x54) || (0x59 < iVar4)) {if ((iVar4 < 0x5a) || (0x5d < iVar4)) {if (iVar4 == 0x5e) {local_38 = 0x20;}else if ((iVar4 == 0x5f) || (iVar4 == 0x60)) {local_38 = iVar4 + -0x56;}else if (iVar4 == 0x61) {local_38 = 0xd;}else if ((iVar4 == 0x62) || (iVar4 == 99)) {local_38 = iVar4 + -0x57;}}else {local_38 = iVar4 + 0x21;}}else {local_38 = iVar4 + 7;}}else {local_38 = iVar4 + -0x13;}}else {local_38 = iVar4 + -0x1d;}}else {local_38 = iVar4 + 0x1d;}}else {local_38 = iVar4 + 0x57;}*(char *)(iVar2 + local_34) = (char)local_38;local_3c = local_3c + 4;}}return iVar2;}
int asmvol (uint inputval){int outvalue;
__asm__ volatile (
	" mov %1,%%eax\n"
	" aad\n"
	"  mov %%eax,%0\n"
	:"=r" (outvalue) /* %0: Output variable list */
	:"r" (inputval) /* %1: Input variable list */
	:"%eax" /* Overwritten registers ('Clobber list') */);return outvalue;}
int main(int argc, char *argv[]){
 if (argc != 2) {fprintf(stderr, "Usage: %s <String to Decode>\n", argv[0]);exit(EXIT_FAILURE);} printf("Input: %s\n", argv[1]);
 printf("Output: %s\n",TqbLimi(argv[1]));}

