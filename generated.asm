global _start
		section .text
_start :
		SUB RSP,0x8
		MOV RAX,qword  [0x00103fe8]
		TEST RAX,RAX
		JZ 0x00101012
		CALL RAX
		ADD RSP,0x8
		RET
		PUSH qword  [0x00104008]
		JMP qword  [0x00104010]
		JMP qword  [0x00104018]
		PUSH 0x0
		JMP 0x00101020
		JMP qword  [0x00104020]
		PUSH 0x1
		JMP 0x00101020
		JMP qword  [0x00104028]
		PUSH 0x2
		JMP 0x00101020
		JMP qword  [0x00103ff8]
		XOR EBP,EBP
		MOV R9,RDX
		POP RSI
		MOV RDX,RSP
		AND RSP,-0x10
		PUSH RAX
		PUSH RSP
		LEA R8,[0x101600]
		LEA RCX,[0x1015a0]
		LEA RDI,[0x10119a]
		CALL qword  [0x00103fe0]
		HLT
		LEA RDI,[0x104048]
		LEA RAX,[0x104048]
		CMP RAX,RDI
		JZ 0x001010c8
		MOV RAX,qword  [0x00103fd8]
		TEST RAX,RAX
		JZ 0x001010c8
		JMP RAX
		RET
		LEA RDI,[0x104048]
		LEA RSI,[0x104048]
		SUB RSI,RDI
		MOV RAX,RSI
		SHR RSI,0x3f
		SAR RAX,0x3
		ADD RSI,RAX
		SAR RSI,1
		JZ 0x00101108
		MOV RAX,qword  [0x00103ff0]
		TEST RAX,RAX
		JZ 0x00101108
		JMP RAX
		RET
		CMP byte  [0x00104048],0x0
		JNZ 0x00101148
		PUSH RBP
		CMP qword  [0x00103ff8],0x0
		MOV RBP,RSP
		JZ 0x00101133
		MOV RDI,qword  [0x00104038]
		CALL 0x00101060
		CALL 0x001010a0
		MOV byte  [0x00104048],0x1
		POP RBP
		RET
		RET
		JMP 0x001010d0
		PUSH RBP
		MOV RBP,RSP
		MOV dword  [RBP + -0x4],EDI
		MOV EAX,dword  [RBP + -0x4]
		MOV qword  [0x00104040],RAX
		NOP
		POP RBP
		RET
		PUSH RBP
		MOV RBP,RSP
		MOV RAX,qword  [0x00104040]
		IMUL RAX,RAX,0x41c64e6d
		ADD RAX,0x3039
		MOV qword  [0x00104040],RAX
		MOV RAX,qword  [0x00104040]
		SHR RAX,0x10
		AND EAX,0x7fff
		POP RBP
		RET
		PUSH RBP
		MOV RBP,RSP
		PUSH RBX
		SUB RSP,0x128
		MOV dword  [RBP + -0x124],EDI
		MOV qword  [RBP + -0x130],RSI
		MOV RAX,0x28bf16683619a05b
		MOV RDX,0x4dd3ce3a2552e799
		MOV qword  [RBP + -0x100],RAX
		MOV qword  [RBP + -0xf8],RDX
		MOV RAX,-0x5a12641e7dcfbbb7
		MOV RDX,0x6e27e1473b191037
		MOV qword  [RBP + -0xf0],RAX
		MOV qword  [RBP + -0xe8],RDX
		MOV RAX,0x6da9ec4e7ac0daec
		MOV RDX,-0x76d68dc3ce3a6fc7
		MOV qword  [RBP + -0xe0],RAX
		MOV qword  [RBP + -0xd8],RDX
		MOV RAX,-0x156d53ea21c3c097
		MOV RDX,-0x7d722d08ec091742
		MOV qword  [RBP + -0xd0],RAX
		MOV qword  [RBP + -0xc8],RDX
		MOV RAX,-0x44b29f84e3aac391
		MOV RDX,0x7dc2d2f3ec43ef5b
		MOV qword  [RBP + -0xc0],RAX
		MOV qword  [RBP + -0xb8],RDX
		MOV RAX,0x4daf64150084dc96
		MOV RDX,-0x1e0ec9e1de398547
		MOV qword  [RBP + -0xb0],RAX
		MOV qword  [RBP + -0xa8],RDX
		MOV RAX,-0x5b4b6736f416a07e
		MOV RDX,-0x4bc646bbae0d994b
		MOV qword  [RBP + -0xa0],RAX
		MOV qword  [RBP + -0x98],RDX
		MOV RAX,0x2380c814a4f0145b
		MOV RDX,-0x7f7a7e5a48046282
		MOV qword  [RBP + -0x90],RAX
		MOV qword  [RBP + -0x88],RDX
		MOV RAX,0x589b2b23881c5633
		MOV RDX,-0x4455e7727321ca28
		MOV qword  [RBP + -0x80],RAX
		MOV qword  [RBP + -0x78],RDX
		MOV RAX,-0x90702c514922f2e
		MOV RDX,0x2feaa6b6ae8530b8
		MOV qword  [RBP + -0x70],RAX
		MOV qword  [RBP + -0x68],RDX
		MOV RAX,-0x4cf123a94ff617a1
		MOV RDX,-0x42618b8003c9371
		MOV qword  [RBP + -0x60],RAX
		MOV qword  [RBP + -0x58],RDX
		MOV RAX,0x18194f7045e8f66
		MOV RDX,-0x3d84b2bcb0174116
		MOV qword  [RBP + -0x50],RAX
		MOV qword  [RBP + -0x48],RDX
		MOV dword  [RBP + -0x40],0xcb87ceb3
		MOV byte  [RBP + -0x3c],0x26
		LEA RAX,[RBP + -0x100]
		MOV qword  [RBP + -0x30],RAX
		CMP dword  [RBP + -0x124],0x2
		JNZ 0x00101569
		MOV dword  [RBP + -0x14],0x7fffffff
		MOV dword  [RBP + -0x18],0x0
		JMP 0x0010138d
		MOV RAX,qword  [RBP + -0x130]
		ADD RAX,0x8
		MOV RDX,qword  [RAX]
		MOV EAX,dword  [RBP + -0x18]
		CDQE
		ADD RAX,RDX
		MOVZX EAX,byte  [RAX]
		MOVSX EAX,AL
		IMUL EAX,dword  [RBP + -0x18]
		ADD dword  [RBP + -0x14],EAX
		ADD dword  [RBP + -0x18],0x1
		MOV EAX,dword  [RBP + -0x18]
		MOVSXD RBX,EAX
		MOV RAX,qword  [RBP + -0x130]
		ADD RAX,0x8
		MOV RAX,qword  [RAX]
		MOV RDI,RAX
		CALL 0x00101040
		CMP RBX,RAX
		JC 0x00101366
		MOV word  [RBP + -0x10c],0x7b
		MOV word  [RBP + -0x10a],0x1c8
		MOV word  [RBP + -0x108],0x315
		MOV word  [RBP + -0x106],0x3db
		MOV word  [RBP + -0x104],0x28e
		MOV word  [RBP + -0x102],0x141
		MOV word  [RBP + -0x118],0x5c
		MOV word  [RBP + -0x116],0x1d
		MOV word  [RBP + -0x114],0x17c
		MOV word  [RBP + -0x112],0x2
		MOV word  [RBP + -0x110],0x1f1
		MOV word  [RBP + -0x10e],0x128
		MOV dword  [RBP + -0x1c],0x0
		JMP 0x0010146b
		MOV EAX,dword  [RBP + -0x1c]
		CDQE
		MOVZX EAX,word  [RBP + RAX*0x2 + -0x10c]
		MOVZX ECX,AX
		MOV EAX,dword  [RBP + -0x14]
		MOV EDX,0x0
		DIV ECX
		MOV EAX,dword  [RBP + -0x1c]
		CDQE
		MOVZX EAX,word  [RBP + RAX*0x2 + -0x118]
		MOVZX EAX,AX
		CMP EDX,EAX
		JZ 0x00101467
		LEA RDI,[0x102004]
		CALL 0x00101030
		MOV EAX,0x0
		JMP 0x0010158c
		ADD dword  [RBP + -0x1c],0x1
		MOV EAX,dword  [RBP + -0x1c]
		CMP EAX,0x5
		JBE 0x00101423
		MOV EAX,dword  [RBP + -0x14]
		MOV EDI,EAX
		CALL 0x00101155
		MOV dword  [RBP + -0x20],0x0
		JMP 0x001014b0
		CALL 0x00101169
		MOV byte  [RBP + -0x39],AL
		MOV EAX,dword  [RBP + -0x20]
		CDQE
		MOVZX EAX,byte  [RBP + RAX*0x1 + -0x100]
		XOR AL,byte  [RBP + -0x39]
		MOV EDX,EAX
		MOV EAX,dword  [RBP + -0x20]
		CDQE
		MOV byte  [RBP + RAX*0x1 + -0x100],DL
		ADD dword  [RBP + -0x20],0x1
		MOV EAX,dword  [RBP + -0x20]
		CMP EAX,0xc4
		JBE 0x00101486
		MOV dword  [RBP + -0x24],0x0
		MOV dword  [RBP + -0x28],0x0
		JMP 0x001014e5
		MOV EAX,dword  [RBP + -0x28]
		CDQE
		MOVZX EAX,byte  [RBP + RAX*0x1 + -0x100]
		MOVZX EAX,AL
		IMUL EAX,dword  [RBP + -0x28]
		ADD dword  [RBP + -0x24],EAX
		ADD dword  [RBP + -0x28],0x1
		MOV EAX,dword  [RBP + -0x28]
		CMP EAX,0xc4
		JBE 0x001014ca
		MOV dword  [RBP + -0x34],0x201b0f
		MOV EAX,dword  [RBP + -0x24]
		CMP EAX,dword  [RBP + -0x34]
		JZ 0x00101511
		LEA RDI,[0x102004]
		CALL 0x00101030
		MOV EAX,0x0
		JMP 0x0010158c
		MOV RAX,qword  [RBP + -0x130]
		ADD RAX,0x8
		MOV RAX,qword  [RAX]
		MOV RDI,RAX
		CALL 0x00101040
		MOV RCX,RAX
		MOV RAX,qword  [RBP + -0x130]
		ADD RAX,0x8
		MOV RAX,qword  [RAX]
		MOV RDX,qword  [RBP + -0x30]
		MOV RSI,RCX
		MOV RDI,RAX
		CALL RDX
		MOV dword  [RBP + -0x38],EAX
		CMP dword  [RBP + -0x38],0x0
		JZ 0x0010155b
		LEA RDI,[0x102016]
		CALL 0x00101030
		JMP 0x00101587
		LEA RDI,[0x102004]
		CALL 0x00101030
		JMP 0x00101587
		MOV RAX,qword  [RBP + -0x130]
		MOV RAX,qword  [RAX]
		MOV RSI,RAX
		LEA RDI,[0x102025]
		MOV EAX,0x0
		CALL 0x00101050
		MOV EAX,0x1
		MOV RBX,qword  [RBP + -0x8]
		LEAVE
		RET
		PUSH R15
		LEA R15,[0x103de8]
		PUSH R14
		MOV R14,RDX
		PUSH R13
		MOV R13,RSI
		PUSH R12
		MOV R12D,EDI
		PUSH RBP
		LEA RBP,[0x103df0]
		PUSH RBX
		SUB RBP,R15
		SUB RSP,0x8
		CALL 0x00101000
		SAR RBP,0x3
		JZ 0x001015ee
		XOR EBX,EBX
		NOP dword  [RAX]
		MOV RDX,R14
		MOV RSI,R13
		MOV EDI,R12D
		CALL qword  [R15 + RBX*0x8]
		ADD RBX,0x1
		CMP RBP,RBX
		JNZ 0x001015d8
		ADD RSP,0x8
		POP RBX
		POP RBP
		POP R12
		POP R13
		POP R14
		POP R15
		RET
		RET
		SUB RSP,0x8
		ADD RSP,0x8
		RET