#include "pch.h" // create this
#include <cstdint>
#include <winternl.h>
#include <tchar.h>
#include <algorithm>
#include <string.h>
 // xorstr  if you cannot find the file or not sure how to work it, cntrl f and search  and delete all of them
//https://pastebin.com/wmXAJ64Y














// If you got sold this please chargeback,
#pragma comment(lib, "user32.lib")
#define DEBASE(a) ((size_t)a - (size_t)(unsigned long long)GetModuleHandleA(NULL))
 
uintptr_t dwProcessBase;
uint64_t backup = 0, Online_Loot__GetItemQuantity = 0, stackFix = 0;
NTSTATUS(*NtContinue)(PCONTEXT threadContext, BOOLEAN raiseAlert) = nullptr;
 
DWORD64 resolveRelativeAddress(DWORD64 instr, DWORD offset, DWORD instrSize) {
    return instr == 0ui64 ? 0ui64 : (instr + instrSize + *(int*)(instr + offset));
}
 
bool compareByte(const char* pData, const char* bMask, const char* szMask) {
    for (; *szMask; ++szMask, ++pData, ++bMask)
        if (*szMask == 'x' && *pData != *bMask)
            return false;
    return (*szMask) == NULL;
}
 
DWORD64 findPattern(DWORD64 dwAddress, DWORD64 dwLen, const char* bMask, const char* szMask) {
    DWORD length = (DWORD)strlen(szMask);
    for (DWORD i = 0; i < dwLen - length; i++)
        if (compareByte((const char*)(dwAddress + i), bMask, szMask))
            return (DWORD64)(dwAddress + i);
    return 0ui64;
}
 
LONG WINAPI TopLevelExceptionHandler(PEXCEPTION_POINTERS pExceptionInfo)
{
    if (pExceptionInfo && pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION)
    {
        if (pExceptionInfo->ContextRecord->R11 == 0xDEEDBEEF89898989)
        {
            pExceptionInfo->ContextRecord->R11 = backup;
 
            if (pExceptionInfo->ContextRecord->Rip > Online_Loot__GetItemQuantity && pExceptionInfo->ContextRecord->Rip < (Online_Loot__GetItemQuantity + 0x1000))
            {
                pExceptionInfo->ContextRecord->Rip = stackFix;
                pExceptionInfo->ContextRecord->Rax = 1;
            }
            NtContinue(pExceptionInfo->ContextRecord, 0);
        }
    }
 
    return EXCEPTION_CONTINUE_SEARCH;
}
 
void SetupExceptionHook()
{
    HMODULE ntdll = GetModuleHandleA("ntdll");
    NtContinue = (decltype(NtContinue))GetProcAddress(ntdll, ("NtContinue"));
 
    void(*RtlAddVectoredExceptionHandler)(LONG First, PVECTORED_EXCEPTION_HANDLER Handler) = (decltype(RtlAddVectoredExceptionHandler))GetProcAddress(ntdll, ("RtlAddVectoredExceptionHandler"));
    RtlAddVectoredExceptionHandler(0, TopLevelExceptionHandler);
 
    uint64_t FindOnline_Loot__GetItemQuantity = findPattern(dwProcessBase + 0x1000000, 0xF000000, ("\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x8B\xC8\xC5\xF0\x57\xC9\xC4\xE1\xF3\x2A\xC9"), ("xxx????x????xxxxxxxxxxx"));
 
    if (FindOnline_Loot__GetItemQuantity)
    {
        Online_Loot__GetItemQuantity = resolveRelativeAddress(FindOnline_Loot__GetItemQuantity + 7, 1, 5);
 
        uint64_t FindDvar = findPattern(Online_Loot__GetItemQuantity, 0x1000, ("\x4C\x8B\x1D"), ("xxx"));
        uint64_t FindStackFix = findPattern(Online_Loot__GetItemQuantity, 0x2000, ("\xE8\x00\x00\x00\x00\x00\x8B\x00\x00\x00\x00\x8B"), ("x?????x????x")); // fat ass sig scan
 
        if (FindStackFix)
        {
            stackFix = (FindStackFix + 5);
 
            backup = *(uint64_t*)resolveRelativeAddress(FindDvar, 3, 7);
            *(uint64_t*)resolveRelativeAddress(FindDvar, 3, 7) = 0xDEEDBEEF89898989; // avg 1337 paster shit yur
        }
    }
}
 
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)// when dll is injected
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {// if DLL is attached to process, call GetModuleHandle and Unlock All for a instant unlocking process..
        dwProcessBase = (uintptr_t)(GetModuleHandle(0)); // getting process base
        SetupExceptionHook(); // calling unlock all
    }
    return TRUE;
}
