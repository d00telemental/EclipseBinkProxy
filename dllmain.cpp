#include <cstdio>
#include <string>
#include <unordered_map>
#include "MinHook/include/MinHook.h"
#include "dllmain.hpp"


FILE* gp_fileHandle = nullptr;
std::unordered_map<HANDLE, std::wstring> g_openedFileHandles;


typedef HANDLE(WINAPI* CreateFileW_t)
(
    LPCWSTR                                     lpFileName,
    DWORD                                       dwDesiredAccess,
    DWORD                                       dwShareMode,
    LPSECURITY_ATTRIBUTES                       lpSecurityAttributes,
    DWORD                                       dwCreationDisposition,
    DWORD                                       dwFlagsAndAttributes,
    HANDLE                                      hTemplateFile
);

CreateFileW_t CreateFileW_orig = nullptr;

HANDLE WINAPI CreateFileW_hook
(
    [[maybe_unused]] LPCWSTR                    lpFileName,
    [[maybe_unused]] DWORD                      dwDesiredAccess,
    [[maybe_unused]] DWORD                      dwShareMode,
    [[maybe_unused]] LPSECURITY_ATTRIBUTES      lpSecurityAttributes,
    [[maybe_unused]] DWORD                      dwCreationDisposition,
    [[maybe_unused]] DWORD                      dwFlagsAndAttributes,
    [[maybe_unused]] HANDLE                     hTemplateFile
)
{
    FILE_WRITE(L"'CreateFileW': %s, access = 0x%X", lpFileName, dwDesiredAccess);
    HANDLE const FileHandle = CreateFileW_orig(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    g_openedFileHandles.insert_or_assign(FileHandle, std::wstring(lpFileName));
    return FileHandle;
}


typedef BOOL(WINAPI* CloseHandle_t)
(
    HANDLE                                      hObject
);

CloseHandle_t CloseHandle_orig = nullptr;

BOOL WINAPI CloseHandle_hook
(
    [[maybe_unused]] HANDLE                     const hObject
)
{
    auto const MappedIter = g_openedFileHandles.find(hObject);
    if (MappedIter != g_openedFileHandles.end()) [[unlikely]]
    {
        FILE_WRITE(L"'CloseHandle': %s", MappedIter->second.c_str());
        g_openedFileHandles.erase(MappedIter);
    }

    return CloseHandle_orig(hObject);
}


DWORD WINAPI OnAttachThread
(
    [[maybe_unused]] LPVOID                     const lpParameter
)
{
    {
        ::AllocConsole();

        ::freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);
        ::freopen_s((FILE**)stderr, "CONOUT$", "w", stderr);

        HANDLE const Console = GetStdHandle(STD_OUTPUT_HANDLE);
        CONSOLE_SCREEN_BUFFER_INFO lpConsoleScreenBufferInfo;
        GetConsoleScreenBufferInfo(Console, &lpConsoleScreenBufferInfo);
        SetConsoleScreenBufferSize(Console, { lpConsoleScreenBufferInfo.dwSize.X, 30000 });
    }

    LOG_INFO(L"hello there, %s!", L"eclipse");

    gp_fileHandle = ::fopen("./binkproxy.log", "w+");
    LOG_INFO(L"opened log file at %p", gp_fileHandle);

    MH_STATUS Status = MH_Initialize();
    if (Status == MH_OK)
    {
        Status = MH_CreateHookApi(L"kernel32.dll", "CreateFileW", CreateFileW_hook, (LPVOID*)&CreateFileW_orig);
        if (Status == MH_OK) LOG_INFO(L"installed hook on 'CreateFileW': %p -> %p", (void*)CreateFileW_orig, (void*)CreateFileW_hook);
        else LOG_ERROR(L"failed to install hook on 'CreateFileW': %S", MH_StatusToString(Status));

        Status = MH_CreateHookApi(L"kernel32.dll", "CloseHandle", CloseHandle_hook, (LPVOID*)&CloseHandle_orig);
        if (Status == MH_OK) LOG_INFO(L"installed hook on 'CloseHandle': %p -> %p", (void*)CloseHandle_orig, (void*)CloseHandle_hook);
        else LOG_ERROR(L"failed to install hook on 'CloseHandle': %S", MH_StatusToString(Status));

        Status = MH_EnableHook(MH_ALL_HOOKS);
        if (Status != MH_OK) LOG_ERROR(L"failed to enable all hooks: %S", MH_StatusToString(Status));
    }
    else
    {
        LOG_ERROR(L"failed to initialize MinHook library: %S", MH_StatusToString(Status));
    }

    return TRUE;
}

BOOL APIENTRY DllMain
(
    [[maybe_unused]] HMODULE                    const hModule,
    [[maybe_unused]] DWORD                      const dwReasonForCall,
    [[maybe_unused]] LPVOID                     const lpReserved
)
{
    switch (dwReasonForCall)
    {
    case DLL_PROCESS_ATTACH:
        //::CreateThread(nullptr, 0, OnAttachThread, nullptr, 0, nullptr);
        OnAttachThread(nullptr);
        break;
    case DLL_PROCESS_DETACH:
        FILE_FLUSH();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }

    return TRUE;
}

