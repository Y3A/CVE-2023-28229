#include <Windows.h>
#include <stdio.h>

#include "rpc.h"

#define RPC_SUCCESS(x) (x == RPC_S_OK)

void __RPC_FAR *__RPC_USER midl_user_allocate(size_t cBytes)
{
    return((void __RPC_FAR *) malloc(cBytes));
}

void __RPC_USER midl_user_free(void __RPC_FAR *p)
{
    free(p);
}

RPC_BINDING_HANDLE GetBindingHandle(void)
{
    RPC_STATUS          status = RPC_S_OK;
    RPC_WSTR            stringBinding = NULL;
    RPC_BINDING_HANDLE  hBinding = NULL;

    status = RpcStringBindingComposeW(
        NULL,
        L"ncalrpc",
        NULL,
        NULL,
        NULL,
        &stringBinding
    );
    if (!RPC_SUCCESS(status)) {
        printf("[-] RpcStringBindingCompose Error : 0x%08X\n", status);
        goto out;
    }

    status = RpcBindingFromStringBindingW(
        stringBinding,
        &hBinding
    );
    if (!RPC_SUCCESS(status)) {
        printf("[-] RpcBindingFromStringBinding Error : 0x%08X\n", status);
        goto out;
    }

out:
    if (stringBinding)
        RpcStringFree(&stringBinding);

    return hBinding;
}

RPC_STATUS CreateContextObject(RPC_BINDING_HANDLE hBinding, PVOID *ContextHandle)
{
    RPC_STATUS status = RPC_S_OK;

    __try {
        status = Proc0_s_SrvRpcCreateContext(hBinding, ContextHandle);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = RpcExceptionCode();
        printf("[-] SrvRpcCryptCreateContext Error : 0x%08X\n", status);
    }

    return status;
}

RPC_STATUS FreeContextObject(RPC_BINDING_HANDLE hBinding, PVOID *ContextHandle)
{
    RPC_STATUS status = RPC_S_OK;

    __try {
        status = Proc1_s_SrvRpcReleaseContext(hBinding, ContextHandle);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = RpcExceptionCode();
        printf("[-] SrvRpcCryptReleaseContext Error : 0x%08X\n", status);
    }

    return status;
}

RPC_STATUS CreateProviderObject(RPC_BINDING_HANDLE hBinding, PVOID ContextHandle, PVOID *ProviderHandle)
{
    RPC_STATUS status = RPC_S_OK;

    __try {
        status = Proc2_s_SrvRpcCryptOpenStorageProvider(hBinding, ContextHandle, ProviderHandle, MS_KEY_STORAGE_PROVIDER, 0);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = RpcExceptionCode();
        printf("[-] SrvRpcCryptOpenStorageProvider Error : 0x%08X\n", status);
    }

    return status;
}

RPC_STATUS FreeProviderObject(RPC_BINDING_HANDLE hBinding, PVOID ContextHandle, PVOID ProviderHandle)
{
    RPC_STATUS status = RPC_S_OK;

    __try {
        status = Proc7_s_SrvRpcCryptFreeProvider(hBinding, ContextHandle, ProviderHandle);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = RpcExceptionCode();
        printf("[-] SrvRpcCryptFreeProvider Error : 0x%08X\n", status);
    }

    return status;
}

RPC_STATUS CreatePersistedKey(RPC_BINDING_HANDLE hBinding, PVOID ContextHandle, PVOID ProviderHandle, PVOID *KeyHandle)
{
    RPC_STATUS status = RPC_S_OK;

    __try {
        status = Proc10_s_SrvRpcCryptCreatePersistedKey(hBinding, ContextHandle, ProviderHandle, KeyHandle, BCRYPT_3DES_ALGORITHM, NULL, 0, 0);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = RpcExceptionCode();
        //    printf("[-] SrvRpcCryptCreatePersistedKey Error : 0x%08X\n", status);
    }

    return status;
}

RPC_STATUS FreePersistedKey(RPC_BINDING_HANDLE hBinding, PVOID ContextHandle, PVOID ProviderHandle, PVOID KeyHandle)
{
    RPC_STATUS status = RPC_S_OK;

    __try {
        status = Proc8_s_SrvRpcCryptFreeKey(hBinding, ContextHandle, ProviderHandle, KeyHandle);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = RpcExceptionCode();
        //    printf("[-] SrvRpcCryptFreeKey Error : 0x%08X\n", status);
    }

    return status;
}

RPC_STATUS GetUseContextProperty(RPC_BINDING_HANDLE hBinding, PVOID ContextHandle, PVOID ProviderHandle, PVOID Buffer, DWORD BufferSize, PDWORD Written)
{
    RPC_STATUS status = RPC_S_OK;

    __try {
        status = Proc11_s_SrvRpcCryptGetProviderProperty(hBinding, ContextHandle, ProviderHandle, NCRYPT_USE_CONTEXT_PROPERTY, Buffer, BufferSize, Written, 0);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = RpcExceptionCode();
        printf("[-] SrvRpcCryptGetProviderProperty Error : 0x%08X\n", status);
    }

    return status;
}

RPC_STATUS SetUseContextProperty(RPC_BINDING_HANDLE hBinding, PVOID ContextHandle, PVOID ProviderHandle, PVOID Buffer, DWORD BufferSize)
{
    RPC_STATUS status = RPC_S_OK;

    __try {
        status = Proc12_s_SrvRpcCryptSetProviderProperty(hBinding, ContextHandle, ProviderHandle, NCRYPT_USE_CONTEXT_PROPERTY, Buffer, BufferSize, 0);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = RpcExceptionCode();
        printf("[-] SrvRpcCryptSetProviderProperty Error : 0x%08X\n", status);
    }

    return status;
}

RPC_STATUS SetRandomProperty(RPC_BINDING_HANDLE hBinding, PVOID ContextHandle, PVOID ProviderHandle, PVOID Buffer, DWORD BufferSize)
{
    RPC_STATUS status = RPC_S_OK;

    __try {
        status = Proc12_s_SrvRpcCryptSetProviderProperty(hBinding, ContextHandle, ProviderHandle, L"AJIDajise93892", Buffer, BufferSize, 0);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = RpcExceptionCode();
        printf("[-] SrvRpcCryptSetProviderProperty Error : 0x%08X\n", status);
    }

    return status;
}

RPC_STATUS CreateMemoryBuffer(RPC_BINDING_HANDLE hBinding, PVOID ContextHandle, PVOID ProviderHandle, PULONG_PTR Buffer)
{
    RPC_STATUS      status = RPC_S_OK;
    NCryptKeyName *unused = NULL;

    __try {
        status = Proc5_s_SrvRpcCryptEnumKeys(hBinding, ContextHandle, ProviderHandle, NULL, &unused, Buffer, 0);
        FreeMemoryBuffer(hBinding, ContextHandle, unused);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = RpcExceptionCode();
        printf("[-] SrvRpcCryptEnumKeys Error : 0x%08X\n", status);
    }

    return status;
}

RPC_STATUS FreeMemoryBuffer(RPC_BINDING_HANDLE hBinding, PVOID ContextHandle, ULONG_PTR Buffer)
{
    RPC_STATUS      status = RPC_S_OK;

    __try {
        status = Proc6_s_SrvRpcCryptFreeBuffer(hBinding, ContextHandle, Buffer);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = RpcExceptionCode();
        printf("[-] SrvRpcCryptFreeBuffer Error : 0x%08X\n", status);
    }

    return status;
}