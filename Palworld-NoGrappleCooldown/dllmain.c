// For Palworld v0.5.0.67935
// github.com/x0reaxeax

#include <Windows.h>

#define MAYBE_UNUSED

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
        0xEB, 0x00  // jmp short loc_2E44F91
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

