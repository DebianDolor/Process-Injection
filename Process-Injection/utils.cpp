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


void XOR(unsigned char* data, size_t data_len, const char* key, size_t key_len) {
    int j = 0;
    for (size_t i = 0; i < data_len; i++) {
        if (j == key_len) j = 0;
        data[i] = data[i] ^ key[j];
        j++;
    }
}


LPCSTR DAndP(unsigned char* encoded, size_t len, const char* key, size_t key_len) {
    char* decoded = new char[len + 1];
    memcpy(decoded, encoded, len);
    XOR(reinterpret_cast<unsigned char*>(decoded), len, key, key_len);
    decoded[len] = '\0';
    return decoded;

}


HANDLE GetProcessHandle(const wchar_t* processName) {
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);  // Take a snapshot of all processes
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        std::wcerr << L"Failed to create process snapshot." << std::endl;
        return NULL;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hProcessSnap, &pe32)) {  // Retrieve the first process information
        std::wcerr << L"Failed to retrieve the first process information." << std::endl;
        CloseHandle(hProcessSnap);
        return NULL;
    }

    do {
        if (_wcsicmp(pe32.szExeFile, processName) == 0) {  // Compare process name with "explorer.exe"
            HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
            if (hProcess == NULL) {
                std::wcerr << L"Failed to open process handle for " << processName << L". Error: " << GetLastError() << std::endl;
            }
            else {
                CloseHandle(hProcessSnap);  // Close snapshot handle after use
                return hProcess;  // Return the handle to the explorer.exe process
            }
        }
    } while (Process32NextW(hProcessSnap, &pe32));  // Continue to the next process

    CloseHandle(hProcessSnap);  // Close snapshot handle if process not found
    std::wcerr << L"Process " << processName << L" not found." << std::endl;
    return NULL;
}

DWORD GetThreadId(DWORD processId) {
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create thread snapshot." << std::endl;
        return 0;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(hThreadSnap, &te32)) {
        std::cerr << "Failed to retrieve the first thread." << std::endl;
        CloseHandle(hThreadSnap);
        return 0;
    }

    DWORD threadId = 0;
    do {
        if (te32.th32OwnerProcessID == processId) {
            threadId = te32.th32ThreadID;
            break; // You may choose a specific thread if desired
        }
    } while (Thread32Next(hThreadSnap, &te32));

    CloseHandle(hThreadSnap);
    return threadId;
}