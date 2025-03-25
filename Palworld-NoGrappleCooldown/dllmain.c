// For Palworld v0.5.0.67935
// github.com/x0reaxeax

#include <Windows.h>

#define MAYBE_UNUSED
#define DLLEXPORT __declspec(dllexport)

HINSTANCE g_hOriginalDll = NULL;

#if defined(TARGET_XINPUT)
typedef DWORD (WINAPI *XInputGetState_t)(DWORD, LPVOID);
typedef DWORD (WINAPI *XInputSetState_t)(DWORD, LPVOID);
typedef DWORD (WINAPI *XInputGetCapabilities_t)(DWORD, DWORD, LPVOID);
typedef VOID  (WINAPI *XInputEnable_t)(BOOL);

XInputGetState_t lpXInputGetState = NULL;
XInputSetState_t lpXInputSetState = NULL;
XInputGetCapabilities_t lpXInputGetCapabilities = NULL;
XInputEnable_t lpXInputEnable = NULL;

EXTERN_C DLLEXPORT DWORD WINAPI XInputGetState(
    DWORD dwUserIndex,
    LPVOID pState
) {
    if (NULL == lpXInputGetState) {
        return ERROR_DEVICE_NOT_CONNECTED;
    }
    return lpXInputGetState(dwUserIndex, pState);
}

EXTERN_C DLLEXPORT DWORD WINAPI XInputSetState(
    DWORD dwUserIndex,
    LPVOID pVibration
) {
    if (NULL == lpXInputSetState) {
        return ERROR_DEVICE_NOT_CONNECTED;
    }
    return lpXInputSetState(dwUserIndex, pVibration);
}

EXTERN_C DLLEXPORT DWORD WINAPI XInputGetCapabilities(
    DWORD dwUserIndex,
    DWORD dwFlags,
    LPVOID pCapabilities
) {
    if (NULL == lpXInputGetCapabilities) {
        return ERROR_DEVICE_NOT_CONNECTED;
    }
    return lpXInputGetCapabilities(dwUserIndex, dwFlags, pCapabilities);
}

EXTERN_C DLLEXPORT void WINAPI XInputEnable(
    BOOL bEnable
) {
    if (NULL == lpXInputEnable) {
        return;
    }
    lpXInputEnable(bEnable);
}
#elif defined(TARGET_DBGCORE)
typedef BOOL (WINAPI *MiniDumpReadDumpStream_t)(
    PVOID,
    ULONG,
    LPVOID,
    PVOID,
    ULONG
);

typedef BOOL (WINAPI *MiniDumpWriteDump_t)(
    HANDLE,
    DWORD,
    HANDLE,
    UINT32,
    LPVOID,
    LPVOID,
    LPVOID
);

MiniDumpReadDumpStream_t lpMiniDumpReadDumpStream = NULL;
MiniDumpWriteDump_t lpMiniDumpWriteDump = NULL;

EXTERN_C DLLEXPORT BOOL WINAPI MiniDumpReadDumpStream(
    PVOID BaseOfDump,
    ULONG StreamNumber,
    LPVOID Dir,
    PVOID Buffer,
    ULONG BufferSize
) {
    if (NULL == lpMiniDumpReadDumpStream) {
        return FALSE;
    }
    return lpMiniDumpReadDumpStream(
        BaseOfDump,
        StreamNumber,
        Dir,
        Buffer,
        BufferSize
    );
}

EXTERN_C DLLEXPORT BOOL WINAPI MiniDumpWriteDump(
    HANDLE hProcess,
    DWORD ProcessId,
    HANDLE hFile,
    UINT32 DumpType,
    LPVOID ExceptionParam,
    LPVOID UserStreamParam,
    LPVOID CallbackParam
) {
    if (NULL == lpMiniDumpWriteDump) {
        return FALSE;
    }
    return lpMiniDumpWriteDump(
        hProcess,
        ProcessId,
        hFile,
        DumpType,
        ExceptionParam,
        UserStreamParam,
        CallbackParam
    );
}
#else
#error "Target not defined, select a valid configuration."
#endif // TARGET

MAYBE_UNUSED VOID SideloadInit(
    VOID
) {
#if defined(TARGET_XINPUT)
    g_hOriginalDll = LoadLibraryA("C:\\Windows\\System32\\XINPUT1_3.dll");
#elif defined(TARGET_DBGCORE)
    g_hOriginalDll = LoadLibraryA("C:\\Windows\\System32\\DBGCORE.DLL");
#endif

    if (NULL == g_hOriginalDll) {
        return;
    }

#if defined(TARGET_XINPUT)
    lpXInputGetState = (XInputGetState_t) GetProcAddress(
        g_hOriginalDll,
        "XInputGetState"
    );

    lpXInputSetState = (XInputSetState_t) GetProcAddress(
        g_hOriginalDll,
        "XInputSetState"
    );

    lpXInputGetCapabilities = (XInputGetCapabilities_t) GetProcAddress(
        g_hOriginalDll,
        "XInputGetCapabilities"
    );

    lpXInputEnable = (XInputEnable_t) GetProcAddress(
        g_hOriginalDll,
        "XInputEnable"
    );

#elif defined(TARGET_DBGCORE)
    lpMiniDumpReadDumpStream = (MiniDumpReadDumpStream_t) GetProcAddress(
        g_hOriginalDll,
        "MiniDumpReadDumpStream"
    );

    lpMiniDumpWriteDump = (MiniDumpWriteDump_t) GetProcAddress(
        g_hOriginalDll,
        "MiniDumpWriteDump"
    );
#endif // TARGET
}

MAYBE_UNUSED LPBYTE AOBScan(
    VOID
) {
    BYTE abTargetBytes[] = {
        0x0F, 0x2F, 0xB6, 0x98, 0x04, 0x00, 0x00,   // comiss xmm6, dword ptr [rsi+498h]
        0x72, 0x20                                  // jb short loc_2E44F91
    };

    LPVOID lpBaseAddress = GetModuleHandle(NULL);
    if (NULL == lpBaseAddress) {
        return NULL;
    }

    MEMORY_BASIC_INFORMATION mbi = { 0 };
    if (EXIT_SUCCESS != VirtualQuery(
        lpBaseAddress,
        &mbi,
        sizeof(mbi)
    )) {
        return NULL;
    }

    LPBYTE lpEndAddress = (LPBYTE) mbi.BaseAddress + mbi.RegionSize;

    for (
        LPBYTE lpCurrentAddress = (LPBYTE) lpBaseAddress;
        lpCurrentAddress < lpEndAddress;
        lpCurrentAddress++
    ) {
        if (EXIT_SUCCESS == memcmp(
            lpCurrentAddress,
            abTargetBytes,
            sizeof(abTargetBytes)
        )) {
            return lpCurrentAddress;
        }
    }

    return NULL;
}

BOOL PatchCooldownTimer(
    VOID
) {
    DWORD64 qwCooldownTimerOffset = 0x2E44F6F;

    CONST BYTE abOriginalBytes[] = {
        0x72, 0x20  // jb short loc_2E44F91
    };

    CONST BYTE abPatchBytes[sizeof(abOriginalBytes)] = {
        0xEB, 0x00  // jmp short loc_2E44F71
    };

    LPBYTE lpBaseAddress = (LPBYTE) GetModuleHandle(NULL);
    if (NULL == lpBaseAddress) {
        return FALSE;
    }

    LPBYTE lpCooldownTimer = lpBaseAddress + qwCooldownTimerOffset;

    if (EXIT_SUCCESS != memcmp(
        lpCooldownTimer,
        abOriginalBytes,
        sizeof(abOriginalBytes)
    )) {
        LPBYTE lpCooldownTimer = AOBScan();
        if (NULL == lpCooldownTimer) {
            return FALSE;
        }

        lpCooldownTimer += 7;
    }

    DWORD dwOldProtect;
    if (!VirtualProtect(
        lpCooldownTimer,
        sizeof(abOriginalBytes),
        PAGE_EXECUTE_READWRITE,
        &dwOldProtect
    )) {
        return FALSE;
    }

    memcpy(
        lpCooldownTimer,
        abPatchBytes,
        sizeof(abPatchBytes)
    );

    if (!VirtualProtect(
        lpCooldownTimer,
        sizeof(abOriginalBytes),
        dwOldProtect,
        &dwOldProtect
    )) {
        return FALSE;
    }

    return TRUE;
}

BOOL APIENTRY DllMain(
    HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH: {
            PatchCooldownTimer();
            break;
        }
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}