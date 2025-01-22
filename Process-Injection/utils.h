#pragma once

#ifndef UTILS_H
#define UTILS_H

#include <windows.h>
#include <tlhelp32.h>
#include <iostream>

DWORD GetProcessIdByName(const wchar_t* processName);

#endif
