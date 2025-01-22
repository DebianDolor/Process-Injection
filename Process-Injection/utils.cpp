#include "utils.h"
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>

DWORD GetProcessIdByName(const wchar_t* processName) {
    // Take a snapshot of all running processes
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::wcerr << L"Failed to create process snapshot. Error: " << GetLastError() << std::endl;
        return 0;
    }

    PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) };

    // Iterate through the processes to find the target process
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, processName) == 0) {
                DWORD pid = pe32.th32ProcessID;
                CloseHandle(hSnapshot);
                return pid;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return 0;
}