// For Palworld v0.5.1.68353
// github.com/x0reaxeax

#include <Windows.h>

#define MAYBE_UNUSED

MAYBE_UNUSED LPBYTE AOBScan(
    VOID
) {
    BYTE abTargetBytes[] = {
        0x0F, 0x2F, 0xB6, 0x98, 0x04, 0x00, 0x00,   // comiss xmm6, dword ptr [rsi+498h]
        0x72, 0x20                                  // jb short loc_2E2E091
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
        lpAddress < lpEnd - sizeof(abTargetBytes);
        ++lpAddress
    ) {
        if (EXIT_SUCCESS == memcmp(
            lpAddress,
            abTargetBytes,
            sizeof(abTargetBytes)
        )) {
            return lpAddress;
        }
    }

    return NULL;
}

BOOL PatchCooldownTimer(
    VOID
) {
    DWORD64 qwCooldownTimerOffset = 0x2E2E06F;

    CONST BYTE abOriginalBytes[] = {
        0x72, 0x20  // jb short loc_2E2E091
    };

    CONST BYTE abPatchBytes[sizeof(abOriginalBytes)] = {
        0xEB, 0x00  // jmp short loc_2E2E091
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

