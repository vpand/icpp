## v0.1.0
Initial release.

## v0.1.1
Bug fixes:
 * icpp: make sure argv[0] is a absolute path in icppcli driver;
 * icpp: fix c source file error compiling arguments;
 * icpp: fix module main.o cache generating error;
 * icpp: fix native module handle wrong loaded order;
 * icpp: fix arm64 windows tls epochptr out of updating error;
 * imod: fix missing calculating module data symbol hashes;
 * imod: fix dll coff file symbol parsing;

Improvements:
 * icpp: add icpp module header directory to clang header search path;
 * icpp: add aarch64 linux ldadd4 runtime functions;
 * imod: add executable binary packing support;
 * imod: add apple framework packing support;
 * imod: add install-prefix configuration to keep packed libraries' original layout;
