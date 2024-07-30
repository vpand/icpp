'''
* Interpreting C++, executing the source and executable like a script */
* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
* Copyright (c) vpand.com 2024. This file is released under LGPL2.
  See LICENSE in root directory for more details
'''

import sys

icpp_patch_magic = "/* Patched by ICPP to use tcgctx tb_ret_addr. */\n"

def patch_qemu_tbret(argv):
    if len(argv) != 2:
        print("Usage: %s /path/to/tcg/aarch64/tcg-target.inc.c" % (argv[0]))
        sys.exit(-1)
    srcf = argv[1]
    with open(srcf, 'r') as fp:
        srcbuf = fp.read()
        if srcbuf.startswith(icpp_patch_magic):
            print("The file %s has already been patched." % (srcf))
            sys.exit(0)
   
    with open(srcf, 'w') as fp:
        fp.write(icpp_patch_magic)
        fp.write(srcbuf.replace('static tcg_insn_unit *tb_ret_addr;', 
                                '//static tcg_insn_unit *tb_bad_ret_addr;')
                       .replace('tb_ret_addr', 's->tb_ret_addr'))
        print("The file %s has been patched." % (srcf))
        sys.exit(0)

if __name__ == "__main__":
    patch_qemu_tbret(sys.argv)
