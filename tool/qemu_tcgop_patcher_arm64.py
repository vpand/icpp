'''
* Interpreting C++, executing the source and executable like a script */
* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
* Copyright (c) vpand.com 2024. This file is released under LGPL2.
  See LICENSE in root directory for more details
'''

import sys

icpp_patch_magic = "/* Patched by ICPP to work correctly on arm64 windows. */\n"

def patch_qemu_tcgop(argv):
    if len(argv) != 2:
        print("Usage: %s /path/to/tcg/tcg-opc.h" % (argv[0]))
        sys.exit(-1)
    srcf = argv[1]
    with open(srcf, 'r') as fp:
        srcbuf = fp.read()
        if srcbuf.startswith(icpp_patch_magic):
            print("The file %s has already been patched." % (srcf))
            sys.exit(0)
   
    with open(srcf, 'w') as fp:
        fp.write(icpp_patch_magic)
        fp.write(srcbuf.replace('#ifdef _MSC_VER', 
                                '#if _MSC_VER && __x86_64__'))
        print("The file %s has been patched." % (srcf))
        sys.exit(0)

if __name__ == "__main__":
    patch_qemu_tcgop(sys.argv)
