#include <stdio.h>
#include <sys/mman.h>

char buf[128];

int main() {
    read(0, buf, 127);
    void *shellcode_mem = mmap(0x16051000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
    strcpy(shellcode_mem, buf);
    ((void(*)())shellcode_mem)();
}
