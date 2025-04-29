// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "MinHook.h"
#include <windows.h>
#include <iostream>
#include "Hooking.Patterns.h"
#include "safetyhook.hpp"
#pragma comment(lib, "libMinHook.x86.lib")
#include "shared.h"
typedef cvar_t*(*Cvar_GetT)(char* var_name, const char* var_value, int flags);
Cvar_GetT Cvar_Get = (Cvar_GetT)0x004337F0;
cvar_t* cg_fovscale;
void codDLLhooks(HMODULE handle);

typedef HMODULE(__cdecl* LoadsDLLsT)(const char* a1, FARPROC* a2, int a3);
LoadsDLLsT originalLoadDLL = nullptr;


SafetyHookInline CG_GetViewFov_og_S{};

void OpenConsole()
{
    AllocConsole();
    freopen("CONOUT$", "w", stdout);
    freopen("CONIN$", "r", stdin);
    std::cout << "Console initialized.\n";
    printf("hi");
}

double CG_GetViewFov_hook() {
    double fov = CG_GetViewFov_og_S.call<double>();
    if (cg_fovscale && cg_fovscale->value)
        fov = fov * cg_fovscale->value;
    return fov;

}

void CheckModule()
{
    HMODULE hMod = GetModuleHandle(L"uo_cgamex86.dll");
    if (hMod)
    {
        std::cout << "uo_cgamex86.dll is attached at address: " << hMod << std::endl;
        codDLLhooks(hMod);
    }
    else
    {
        std::cout << "uo_cgamex86.dll is NOT attached.\n";
    }
}

HMODULE __cdecl hookCOD_dllLoad(const char* a1, FARPROC* a2, int a3) {
    HMODULE result = originalLoadDLL(a1, a2, a3);
    CheckModule();
   // printf("0x%X \n", (int)result);
    return result;
}

void InitHook() {
    cg_fovscale = Cvar_Get((char*)"cg_fovscale", "1.0", CVAR_ARCHIVE);
    if (MH_Initialize() != MH_OK) {
        //MessageBoxW(NULL, L"FAILED TO INITIALIZE", L"Error", MB_OK | MB_ICONERROR);
        return;
    }
    if (MH_CreateHook((void**)0x454440, &hookCOD_dllLoad, (void**)&originalLoadDLL) != MH_OK) {
        //MessageBoxW(NULL, L"FAILED TO HOOK", L"Error", MB_OK | MB_ICONERROR);
        return;
    }
    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
        //MessageBoxW(NULL, L"FAILED TO ENABLE", L"Error", MB_OK | MB_ICONERROR);
        return;
    }

    //MessageBoxW(NULL, L"FAILED TO ENABLE", L"Error", MB_OK | MB_ICONERROR);
}

void codDLLhooks(HMODULE handle) {
   // printf("run");
    uintptr_t OFFSET = (uintptr_t)handle;
    //printf("HANDLE : 0x%p ADDR : 0x%p \n", handle, OFFSET + 0x2CC20);
    CG_GetViewFov_og_S.reset();
    CG_GetViewFov_og_S = safetyhook::create_inline(OFFSET + 0x2CC20, &CG_GetViewFov_hook);
        //if (MH_CreateHook((void**)OFFSET + 0x2CC20, &CG_GetViewFov_hook, (void**)&CG_GetViewFov_og) != MH_OK) {
        //    MessageBoxW(NULL, L"FAILED TO HOOK", L"Error", MB_OK | MB_ICONERROR);
        //    return;
        //}
    
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        InitHook();
        //OpenConsole();
        //CheckModule();
        HMODULE moduleHandle;
        // idk why but this makes it not DETATCH prematurely
        GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCTSTR)DllMain, &moduleHandle);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        //FreeConsole();
        //MH_Uninitialize();
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

