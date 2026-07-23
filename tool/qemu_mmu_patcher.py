'''
* Interpreting C++, executing the source and executable like a script */
* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
* Copyright (c) vpand.com 2024. This file is released under GPLv2.
  See LICENSE in root directory for more details
'''

import sys

icpp_patch_magic = "/* Patched by ICPP to enable the emulated code to access memory directly. */\n"
split_magic = "helper(CPUArchState *env, target_ulong addr"

def patch_qemu_mmu(argv):
    if len(argv) != 2:
        print("Usage: %s /path/to/cputlb.c" % (argv[0]))
        sys.exit(-1)
    srcf = argv[1]
    with open(srcf, 'r') as fp:
        srcbuf = fp.read()
        if srcbuf.startswith(icpp_patch_magic):
            print("The file %s has already been patched." % (srcf))
            sys.exit(0)
    '''
    tb_page_addr_t get_page_addr_code_hostp(CPUArchState *env, target_ulong addr,
                                            void **hostp)
    {
        struct uc_struct *uc = env->uc;
        uintptr_t mmu_idx = cpu_mmu_index(env, true);

    ...

    static uint64_t inline
    load_helper(CPUArchState *env, target_ulong addr, TCGMemOpIdx oi,
            uintptr_t retaddr, MemOp op, bool code_read,
            FullLoadHelper *full_load)
    {

    ...

    static void inline
    store_helper(CPUArchState *env, target_ulong addr, uint64_t val,
             TCGMemOpIdx oi, uintptr_t retaddr, MemOp op)
    {
    ...
    '''
    parts = srcbuf.split(split_magic)
    with open(srcf, 'w') as fp:
        # part0
        fp.write(icpp_patch_magic)
        # added by ICPP version 0.3.0
        # return code page address directly
        v030_split_magic = 'uintptr_t mmu_idx = cpu_mmu_index(env, true);'
        v030_parts = parts[0].split(v030_split_magic)
        fp.write(v030_parts[0])
        fp.write("return addr; // ICPP\n\t")
        fp.write(v030_split_magic)
        fp.write(v030_parts[1])
        # part1
        fp.write(split_magic)
        first_left_curly_brace_pos = parts[1].find('{')
        fp.write(parts[1][0:first_left_curly_brace_pos+1])
        # read memory directly
        # icpp maps the emulated code at the address under 0x10000000
        # so the address larger than 0x10000000 is the running process's memory
        fp.write("\n    if (addr > 0x10000000) { return load_memop((void *)addr, op); }\n")
        fp.write(parts[1][first_left_curly_brace_pos+1:len(parts[1])])
        # part2
        fp.write(split_magic)
        first_left_curly_brace_pos = parts[2].find('{')
        fp.write(parts[2][0:first_left_curly_brace_pos+1])
        # write memory directly
        fp.write("\n    if (addr > 0x10000000) { store_memop((void *)addr, val, op); return; }\n")
        fp.write(parts[2][first_left_curly_brace_pos+1:len(parts[2])])
        # part3...
        i = 3
        while i < len(parts):
            fp.write(split_magic)
            fp.write(parts[i])
            i += 1
        print("The file %s has been patched." % (srcf))
        sys.exit(0)

if __name__ == "__main__":
    patch_qemu_mmu(sys.argv)
