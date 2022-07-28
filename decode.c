#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
/* WARNING: Function: __x86.get_pc_thunk.ax replaced with injection: get_pc_thunk_ax *//* WARNING: Unknown calling convention yet parameter storage is locked */char * KjfNEzxcZ(char *param_1,int param_2,int param_3,int param_4){for (; 0 < param_4; param_4 = param_4 + -1) {*param_1 = *(char *)(param_2 + param_3);param_1 = param_1 + 1;param_2 = param_2 + 1;}*param_1 = '\0';return param_1;}/* WARNING: Function: __x86.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx */int dwpxLuMflFW(char *param_1){int iVar1;int iVar2;int iVar3;uint uVar4;int iVar5;int in_GS_OFFSET;int local_3c;int local_38;int local_34;char local_14 [4];iVar1 = *(int *)(in_GS_OFFSET + 0x14);iVar2 = strlen(param_1);if (iVar2 < 0) {iVar2 = iVar2 + 3;}iVar3 = calloc((iVar2 >> 2) + 1,1);if (iVar3 == 0) {iVar3 = 0;}else {local_3c = 0;for (local_34 = 0; local_34 < iVar2 >> 2; local_34 = local_34 + 1) {KjfNEzxcZ(local_14,param_1,local_3c,4);iVar1 = asmvol(uVar4);uVar4 = strtol(local_14,0,0x10);iVar5 = (int)(uVar4 & 0xffff0000 | (uint)(unsigned char)((char)uVar4 + (char)(uVar4 >> 8) * '\n')) %100;if (iVar5 < 10) {local_38 = iVar5 + 0x30;}else if ((iVar5 < 10) || (0x23 < iVar5)) {if ((iVar5 < 0x24) || (0x3d < iVar5)) {if ((iVar5 < 0x3e) || (0x4c < iVar5)) {if ((iVar5 < 0x4d) || (0x53 < iVar5)) {if ((iVar5 < 0x54) || (0x59 < iVar5)) {if ((iVar5 < 0x5a) || (0x5d < iVar5)) {if (iVar5 == 0x5e) {local_38 = 0x20;}else if ((iVar5 == 0x5f) || (iVar5 == 0x60)) {local_38 = iVar5 + -0x56;}else if (iVar5 == 0x61) {local_38 = 0xd;}else if ((iVar5 == 0x62) || (iVar5 == 99)) {local_38 = iVar5 + -0x57;}}else {local_38 = iVar5 + 0x21;}}else {local_38 = iVar5 + 7;}}else {local_38 = iVar5 + -0x13;}}else {local_38 = iVar5 + -0x1d;}}else {local_38 = iVar5 + 0x1d;}}else {local_38 = iVar5 + 0x57;}*(char *)(iVar3 + local_34) = (char)local_38;local_3c = local_3c + 4;}}return iVar3;}
int asmvol (uint inputval){int outvalue;
__asm__ volatile (
	" mov %1,%%eax\n"
	" aad\n"
	"  mov %%eax,%0\n"
	:"=r" (outvalue) /* %0: Output variable list */
	:"r" (inputval) /* %1: Input variable list */
	:"%eax" /* Overwritten registers ('Clobber list') */);return outvalue;}
int main(int argc, char *argv[]){
 if (argc != 2) {fprintf(stderr, "Usage: %s <String to Decode>\n", argv[0]);exit(EXIT_FAILURE);} printf("\n-- START DECODING --\nInput: %s\n", argv[1]);
 printf("Output: %s\n-- END DECODING --\n\n",dwpxLuMflFW(argv[1]));}

