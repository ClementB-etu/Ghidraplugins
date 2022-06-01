global _start
		section .text
_start :
	xor    ebp,ebp
	mov    rdx,r9
	pop    rsi
	mov    rsp,rdx
	and    -0x10,rsp
	push   rax
	push   rsp
	lea    0x2c6,r8        # 13e0 <__libc_csu_fini>
	lea    0x24f,rcx        # 1370 <__libc_csu_init>
	lea    0x1b2,rdi        # 12da <main>
	# callq  *0x2eb2        # 3fe0 <__libc_start_main@GLIBC_2.2.5>
	# hlt    


 	push   rbp
 	mov    rsp,rbp
 	sub    $0x10,rsp
 	lea    0xd44,rdi        # 2031 <_IO_stdin_used+0x31>
 	callq  11e9 <input>
 	mov    rax,-0x8(rbp)
 	movl   $0x0,-0x10(rbp)
 	movl   $0x0,-0xc(rbp)
 	jmp    1320 <main+0x46>
 	mov    -0xc(rbp),eax
 	movslq eax,rdx
 	mov    -0x8(rbp),rax
 	add    rdx,rax
 	movzbl (rax),eax
 	movsbl al,eax
 	add    eax,-0x10(rbp)
 	addl   $0x1,-0xc(rbp)
 	mov    -0x8(rbp),rax
 	mov    rax,rdi
 	callq  12a8 <len>
 	cmp    eax,-0xc(rbp)
 	jl     1306 <main+0x2c>
 	mov    -0x8(rbp),rax
 	mov    rax,rdi
 	callq  12a8 <len>
 	imul   $0xfffffff6,eax,eax
 	add    $0x34e7,eax
 	cmp    eax,-0x10(rbp)
 	jne    1358 <main+0x7e>
 	lea    0xcf0,rdi        # 2041 <_IO_stdin_used+0x41>
 	callq  10a0 <puts@plt>
 	jmp    1364 <main+0x8a>
 	lea    0xcf5,rdi        # 2054 <_IO_stdin_used+0x54>
 	callq  10a0 <puts@plt>
 	mov    $0x0,eax
 	leaveq 
 	retq   
 	nopl   0x0(rax,rax,1)

