global _start
		section .text
_start :
		MOV EAX,0x1
		MOV EDI,0x1
		MOV RSI,0x402000
		MOV EDX,0xd
		SYSCALL
		MOV EAX,0x3c
		XOR RDI,RDI
		SYSCALL
		section .data
message : db	'Hello, World',10
