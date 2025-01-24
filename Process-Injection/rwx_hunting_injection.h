#pragma once

#ifndef RWX_HUNTING_INJECTION
#define RWX_HUNTING_INJECTION

#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <shlwapi.h>
#include <strsafe.h>
#include <winternl.h>


HANDLE fProc(const char* procname);

void RWXHuntingInjection();

#endif
