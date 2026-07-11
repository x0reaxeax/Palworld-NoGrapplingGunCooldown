// For Palworld v1.0.0.100427
// github.com/x0reaxeax

#include <Windows.h>

#define MAYBE_UNUSED

typedef WORD UMASK16, *PUMASK16, *LPUMASK16;
typedef UMASK16 UMASK, *PUMASK, *LPUMASK;
typedef CONST UMASK CUMASK, *PCUMASK, *LPCUMASK;
typedef CONST UMASK16 CUMASK16, *PCUMASK16, *LPCUMASK16;
typedef UINT64 QWORD64, *PQWORD64, *LPQWORD64;

typedef struct _SEARCH_INFO {
    LPCVOID lpSearchBase;
    SIZE_T dwSearchSize;
} SEARCH_INFO, *PSEARCH_INFO, *LPSEARCH_INFO;;

CONST UMASK awSignature[] = {
    0x0F, 0x2F, 0xB7, '??', '??', 0x00, 0x00,   // comiss xmm6,[rdi+???]
    0x72, '??',                                 // jb short +???
    0x48, 0x8D                                  // lea64
};

#define JMP_OFFSET  0x7U

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

MAYBE_UNUSED LPBYTE AOBScan(
    VOID
) {
    CONST SIZE_T ccbComissInstSize = sizeof(
        (BYTE[]) {
        0x0F, 0x2F, 0xB7, 0x78, 0x05, 0x00, 0x00
    }
    );                                              // comiss xmm6,[rdi+00000578]

    BYTE abTargetBytesComissXmm6[] = {
        0x0F, 0x2F, 0xB7                            // comiss xmm6, dword ptr [rsi+???]
    };

    BYTE abTargetBytesJbShort[] = {
        0x72, 0x5C                                  // jb short +0x5C
    };

    SEARCH_INFO searchInfo = { 0 };
    if (!GetSearchInfo(&searchInfo)) {
        return NULL;
    }

    SIZE_T dwSizeOfImage = searchInfo.dwSearchSize;
    LPBYTE lpStart = (LPBYTE) searchInfo.lpSearchBase;
    LPBYTE lpEnd = lpStart + dwSizeOfImage;
#ifdef _OLD_STAIC_SEARCH
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
#else
    return (LPBYTE) SearchForMaskedSignature(
        searchInfo.lpSearchBase,
        searchInfo.dwSearchSize,
        awSignature,
        ARRAYSIZE(awSignature)
    );
#endif // _OLD_STAIC_SEARCH
}

BOOL PatchCooldownTimer(
    VOID
) {
    CONST BYTE abPatchBytes[] = {
        0xEB, 0x00      // jmp short +0x00
    };

    LPVOID lpCooldownTimer = AOBScan();
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
        sizeof(abPatchBytes),
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
        sizeof(abPatchBytes),
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

