// For Palworld v1.0.0.1XXX
// github.com/x0reaxeax

#include <Windows.h>

#define MAYBE_UNUSED
#define DLLEXPORT __declspec(dllexport)

typedef WORD UMASK16, *PUMASK16, *LPUMASK16;
typedef UMASK16 UMASK, *PUMASK, *LPUMASK;
typedef CONST UMASK16 *PCUMASK16, *LPCUMASK16;
typedef CONST UMASK *PCUMASK, *LPCUMASK;
typedef UINT64 QWORD64, *PQWORD64, *LPQWORD64;

typedef struct _SEARCH_INFO {
    LPCVOID lpSearchBase;
    SIZE_T dwSearchSize;
} SEARCH_INFO, * PSEARCH_INFO, * LPSEARCH_INFO;;

const UMASK awSignature[] = {
    0x0F, 0x2F, 0xB7, '??', '??', 0x00, 0x00,   // comiss xmm6,[rdi+???]
    0x72, '??',                                 // jb short +???
    0x48, 0x8D                                  // lea64
};

#define JMP_OFFSET  0x7U

HINSTANCE g_hOriginalDll = NULL;

MAYBE_UNUSED LPCBYTE SearchForMaskedSignature(
    _In_ LPCVOID lpSearchBase,
    _In_ SIZE_T dwSearchSize,
    _In_ PCUMASK awSignature,
    _In_ SIZE_T dwSignatureSize
) {
    for (SIZE_T i = 0; i < dwSearchSize - dwSignatureSize; i++) {
        BOOLEAN bMatch = TRUE;
        for (SIZE_T j = 0; j < dwSignatureSize; j++) {
            if ('??' != awSignature[j] && ((LPCBYTE) lpSearchBase)[i + j] != (BYTE) awSignature[j]) {
                bMatch = FALSE;
                break;
            }
        }
        if (bMatch) {
            return (LPCBYTE) lpSearchBase + i;
        }
    }
    return NULL;
}

MAYBE_UNUSED static BOOLEAN GetSearchInfo(
    _Out_ LPSEARCH_INFO lpSearchInfo
) {
    if (NULL == lpSearchInfo) {
        return FALSE;
    }

    ZeroMemory(lpSearchInfo, sizeof(SEARCH_INFO));

    HMODULE hModule = GetModuleHandleA(NULL);
    if (NULL == hModule) {
        return FALSE;
    }

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER) hModule;
    if (IMAGE_DOS_SIGNATURE != pDosHeader->e_magic) {
        return FALSE;
    }

    PIMAGE_NT_HEADERS pNtHeaders = \
        (PIMAGE_NT_HEADERS) ((LPBYTE) hModule + pDosHeader->e_lfanew);
    if (IMAGE_NT_SIGNATURE != pNtHeaders->Signature) {
        return FALSE;
    }

    lpSearchInfo->lpSearchBase = (LPCVOID) hModule;
    lpSearchInfo->dwSearchSize = pNtHeaders->OptionalHeader.SizeOfImage;
    return TRUE;
}

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
#elif defined(TARGET_NORMALIZ)
    g_hOriginalDll = LoadLibraryA("C:\\Windows\\System32\\NORMALIZ.DLL");
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
#elif defined(TARGET_DBGCORE)
    lpMiniDumpReadDumpStream = (MiniDumpReadDumpStream_t) GetProcAddress(
    g_hOriginalDll,
    "MiniDumpReadDumpStream"
    );

    lpMiniDumpWriteDump = (MiniDumpWriteDump_t) GetProcAddress(
        g_hOriginalDll,
        "MiniDumpWriteDump"
    );
#else
    #error "Target not defined, select a valid configuration."
#endif // TARGET
}

BOOL PatchCooldownTimer(
    VOID
) {
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

    SEARCH_INFO searchInfo = { 0 };
    if (!GetSearchInfo(&searchInfo)) {
        return FALSE;
    }

    LPBYTE lpCooldownTimer = (LPBYTE) SearchForMaskedSignature(
        searchInfo.lpSearchBase,
        searchInfo.dwSearchSize,
        awSignature,
        ARRAYSIZE(awSignature)
    );

    if (NULL == lpCooldownTimer) {
        return FALSE;
    }

    MEMORY_BASIC_INFORMATION mbi = { 0 };
    if (0 == VirtualQuery(
        lpCooldownTimer,
        &mbi,
        sizeof(mbi)
    )) {
        return FALSE;
    } else {
        if (MEM_COMMIT != mbi.State || PAGE_EXECUTE_READ != mbi.Protect) {
            return FALSE;
        }
    }

    DWORD dwOldProtect;
    if (!VirtualProtect(
        (LPVOID) ((QWORD64) lpCooldownTimer + JMP_OFFSET),
        sizeof(abOriginalBytes),
        PAGE_EXECUTE_READWRITE,
        &dwOldProtect
    )) {
        return FALSE;
    }

    memcpy(
        (LPVOID) ((QWORD64) lpCooldownTimer + JMP_OFFSET),
        abPatchBytes,
        sizeof(abPatchBytes)
    );

    if (!VirtualProtect(
        (LPVOID) ((QWORD64) lpCooldownTimer + JMP_OFFSET),
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