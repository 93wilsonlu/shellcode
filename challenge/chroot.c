#include <stdio.h>
#include <sys/mman.h>

int main() {
    void *shellcode_mem = mmap(0x16051000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
    read(0, shellcode_mem, 1000);
    if (chroot("/tmp") != 0) {
        puts("Need root permission!");
        return 0;
    }
    chdir("/");
    ((void(*)())shellcode_mem)();
}
