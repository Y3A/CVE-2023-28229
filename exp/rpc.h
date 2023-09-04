#pragma once

#define RPC_SUCCESS(x) (x == RPC_S_OK)

RPC_BINDING_HANDLE GetBindingHandle(void);
RPC_STATUS CreateContextObject(RPC_BINDING_HANDLE hBinding, PVOID *ContextHandle);
RPC_STATUS FreeContextObject(RPC_BINDING_HANDLE hBinding, PVOID *ContextHandle);
RPC_STATUS CreateProviderObject(RPC_BINDING_HANDLE hBinding, PVOID ContextHandle, PVOID *ProviderHandle);
RPC_STATUS FreeProviderObject(RPC_BINDING_HANDLE hBinding, PVOID ContextHandle, PVOID ProviderHandle);
RPC_STATUS CreatePersistedKey(RPC_BINDING_HANDLE hBinding, PVOID ContextHandle, PVOID ProviderHandle, PVOID *KeyHandle);
RPC_STATUS FreePersistedKey(RPC_BINDING_HANDLE hBinding, PVOID ContextHandle, PVOID ProviderHandle, PVOID KeyHandle);
RPC_STATUS GetUseContextProperty(RPC_BINDING_HANDLE hBinding, PVOID ContextHandle, PVOID ProviderHandle, PVOID Buffer, DWORD BufferSize, PDWORD Written);
RPC_STATUS SetUseContextProperty(RPC_BINDING_HANDLE hBinding, PVOID ContextHandle, PVOID ProviderHandle, PVOID Buffer, DWORD BufferSize);
RPC_STATUS CreateMemoryBuffer(RPC_BINDING_HANDLE hBinding, PVOID ContextHandle, PVOID ProviderHandle, PULONG_PTR Buffer);
RPC_STATUS FreeMemoryBuffer(RPC_BINDING_HANDLE hBinding, PVOID ContextHandle, ULONG_PTR Buffer);

typedef struct cstmKeyObject
{
    DWORD signature;
    DWORD unknown1;
    int refcount;
    DWORD unknown2;
    LIST_ENTRY link;
    struct cstmProviderObject *provider;
    PVOID someptr;
    ULONG64 handle;
} KEYOBJECT, *PKEYOBJECT;

typedef struct cstmProviderObject
{
    DWORD signature;
    DWORD unknown1;
    int refcount;
    LIST_ENTRY providerLink;
    char unknownBuf1[32];
    void(__stdcall *vtable[13])();
    char unknownBuf2[112];
    char unknownBuf3[8];
    RTL_CRITICAL_SECTION providerLock;
    char unknownBuf4[16];
    DWORD handle;
} PROVIDEROBJECT, *PPROVIDEROBJECT;