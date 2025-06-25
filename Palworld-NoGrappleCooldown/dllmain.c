// For Palworld v0.6.0.75365
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
#elif defined(TARGET_NORMALIZ)
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

typedef INT (WINAPI *IdnToAscii_t)(
    DWORD dwFlags,
    LPCWSTR lpUnicodeCharStr,
    INT cchUnicodeChar,
    LPSTR lpAsciiCharStr,
    INT cchAsciiChar
);

typedef INT (WINAPI *IdnToNameprepUnicode_t)(
    DWORD dwFlags,
    LPCWSTR lpUnicodeCharStr,
    INT cchUnicodeChar,
    LPWSTR lpNameprepCharStr,
    INT cchNameprepChar
);

typedef INT (WINAPI *IdnToUnicode_t)(
    DWORD dwFlags,
    LPCSTR lpAsciiCharStr,
    INT cchAsciiChar,
    LPWSTR lpUnicodeCharStr,
    INT cchUnicodeChar
);

typedef BOOL (WINAPI *IsNormalizedString_t)(
    DWORD dwNormalizationForm,
    LPCWSTR lpString,
    INT cchString
);

typedef INT (WINAPI *NormalizeString_t)(
    DWORD dwNormalizationForm,
    LPCWSTR lpSrcString,
    INT cchSrcString,
    LPWSTR lpDstString,
    INT cchDstString
);

IdnToAscii_t lpIdnToAscii = NULL;
IdnToNameprepUnicode_t lpIdnToNameprepUnicode = NULL;
IdnToUnicode_t lpIdnToUnicode = NULL;
IsNormalizedString_t lpIsNormalizedString = NULL;
NormalizeString_t lpNormalizeString = NULL;

#pragma warning (disable : 28251)   // Inconsistent annotation
#pragma warning (disable : 6054)    // String might not be zero-terminated
#pragma warning (disable : 4273)    // Inconsistent dll linkage
#pragma warning (disable : 4028)    // Formal parameter list different from declaration
EXTERN_C DLLEXPORT INT WINAPI IdnToAscii(
    DWORD dwFlags,
    LPCWSTR lpUnicodeCharStr,
    INT cchUnicodeChar,
    LPSTR lpAsciiCharStr,
    INT cchAsciiChar
) {
    if (NULL == lpIdnToAscii) {
        return 0;
    }
    return lpIdnToAscii(
        dwFlags, 
        lpUnicodeCharStr, 
        cchUnicodeChar, 
        lpAsciiCharStr, 
        cchAsciiChar
    );
}

EXTERN_C DLLEXPORT INT WINAPI IdnToNameprepUnicode(
    DWORD dwFlags,
    LPCWSTR lpUnicodeCharStr,
    INT cchUnicodeChar,
    LPWSTR lpNameprepCharStr,
    INT cchNameprepChar
) {
    if (NULL == lpIdnToNameprepUnicode) {
        return 0;
    }
    return lpIdnToNameprepUnicode(
        dwFlags, 
        lpUnicodeCharStr, 
        cchUnicodeChar, 
        lpNameprepCharStr, 
        cchNameprepChar
    );
}

EXTERN_C DLLEXPORT INT WINAPI IdnToUnicode(
    DWORD dwFlags,
    LPCSTR lpAsciiCharStr,
    INT cchAsciiChar,
    LPWSTR lpUnicodeCharStr,
    INT cchUnicodeChar
) {
    if (NULL == lpIdnToUnicode) {
        return 0;
    }
    return lpIdnToUnicode(
        dwFlags, 
        lpAsciiCharStr, 
        cchAsciiChar, 
        lpUnicodeCharStr, 
        cchUnicodeChar
    );
}

EXTERN_C DLLEXPORT BOOL WINAPI IsNormalizedString(
    DWORD dwNormalizationForm,
    LPCWSTR lpString,
    INT cchString
) {
    if (NULL == lpIsNormalizedString) {
        return FALSE;
    }
    return lpIsNormalizedString(dwNormalizationForm, lpString, cchString);
}

EXTERN_C DLLEXPORT INT WINAPI NormalizeString(
    DWORD dwNormalizationForm,
    LPCWSTR lpSrcString,
    INT cchSrcString,
    LPWSTR lpDstString,
    INT cchDstString
) {
    if (NULL == lpNormalizeString) {
        return 0;
    }
    return lpNormalizeString(
        dwNormalizationForm, 
        lpSrcString, 
        cchSrcString, 
        lpDstString, 
        cchDstString
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
#elif defined(TARGET_NORMALIZ)
    g_hOriginalDll = LoadLibraryA("C:\\Windows\\System32\\NORMALIZ.DLL");
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

#elif defined(TARGET_NORMALIZ)
    lpIdnToAscii = (IdnToAscii_t) GetProcAddress(
        g_hOriginalDll,
        "IdnToAscii"
    );
    lpIdnToNameprepUnicode = (IdnToNameprepUnicode_t) GetProcAddress(
        g_hOriginalDll,
        "IdnToNameprepUnicode"
    );
    lpIdnToUnicode = (IdnToUnicode_t) GetProcAddress(
        g_hOriginalDll,
        "IdnToUnicode"
    );
    lpIsNormalizedString = (IsNormalizedString_t) GetProcAddress(
        g_hOriginalDll,
        "IsNormalizedString"
    );
    lpNormalizeString = (NormalizeString_t) GetProcAddress(
        g_hOriginalDll,
        "NormalizeString"
    );
#else
    #error "Target not defined, select a valid configuration."
#endif // TARGET
}

MAYBE_UNUSED LPBYTE AOBScan(
    VOID
) {
    CONST SIZE_T ccbComissInstSize = sizeof(
        (BYTE[]) { 0x0F, 0x2F, 0xB6, 0x98, 0x04, 0x00, 0x00 }
    );                                              // comiss xmm6, dword ptr [rsi+498h]

    BYTE abTargetBytesComissXmm6[] = {
        0x0F, 0x2F, 0xB6                            // comiss xmm6, dword ptr [rsi+???]
    };
    
    BYTE abTargetBytesJbShort[] = {
        0x72, 0x20                                  // jb short +0x20
    };

    HMODULE hModule = GetModuleHandleA(NULL);
    if (NULL == hModule) {
        return NULL;
    }

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER) hModule;
    if (IMAGE_DOS_SIGNATURE != pDosHeader->e_magic) {
        return NULL;
    }

    PIMAGE_NT_HEADERS pNtHeaders = \
        (PIMAGE_NT_HEADERS) ((LPBYTE) hModule + pDosHeader->e_lfanew);

    if (IMAGE_NT_SIGNATURE != pNtHeaders->Signature) {
        return NULL;
    }

    SIZE_T dwSizeOfImage = pNtHeaders->OptionalHeader.SizeOfImage;
    LPBYTE lpStart = (LPBYTE) hModule;
    LPBYTE lpEnd = lpStart + dwSizeOfImage;

    for (
        LPBYTE lpAddress = lpStart; 
        lpAddress < lpEnd - ccbComissInstSize + sizeof(abTargetBytesJbShort);
        ++lpAddress
    ) {
        if (EXIT_SUCCESS == memcmp(
            lpAddress, 
            abTargetBytesComissXmm6,
            sizeof(abTargetBytesComissXmm6)
        )) {
            if (EXIT_SUCCESS == memcmp(
                lpAddress + ccbComissInstSize,
                abTargetBytesJbShort,
                sizeof(abTargetBytesJbShort)
            )) {
                return lpAddress;
            }
        }
    }

    return NULL;
}

BOOL PatchCooldownTimer(
    VOID
) {
    DWORD64 qwCooldownTimerOffset = 0x2F2D223;

    CONST BYTE abOriginalBytes[] = {
        0x72, 0x20  // jb short +0x20
    };

    CONST BYTE abPatchBytes[sizeof(abOriginalBytes)] = {
        0xEB, 0x00  // jmp short +0x00
    };

    LPBYTE lpBaseAddress = (LPBYTE) GetModuleHandle(NULL);
    if (NULL == lpBaseAddress) {
        return FALSE;
    }

    LPBYTE lpCooldownTimer = lpBaseAddress + qwCooldownTimerOffset;

    MEMORY_BASIC_INFORMATION mbi = { 0 };
    BOOL bValidMemory = TRUE;
    if (0 == VirtualQuery(
        lpCooldownTimer,
        &mbi,
        sizeof(mbi)
    )) {
        bValidMemory = FALSE;
    } else {
        if (MEM_COMMIT != mbi.State || PAGE_EXECUTE_READ != mbi.Protect) {
            bValidMemory = FALSE;
        }
    }

    if (!bValidMemory || EXIT_SUCCESS != memcmp(
        lpCooldownTimer,
        abOriginalBytes,
        sizeof(abOriginalBytes)
    )) {
        lpCooldownTimer = AOBScan();
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