# CVE-2023-28229

Windows CNG KeyIso RPC EoP/SBX   
Discovered by: [@k0shl](https://twitter.com/KeyZ3r0)   
Reference: https://whereisk0shl.top/post/isolate-me-from-sandbox-explore-elevation-of-privilege-of-cng-key-isolation

![](gg.png)

If compilation fails, rename `rpc.h` to something else because I didn't realise `rpc.h` is a standard include in Windows!
