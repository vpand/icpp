'''
* Interpreting C++, executing the source and executable like a script */
* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
* Copyright (c) vpand.com 2024. This file is released under LGPL2.
  See LICENSE in root directory for more details
'''

import string
import sys

icpp_patch_magic = "// Patched by ICPP to make it compilable on Windows.\n"

def patch_llvm_unicode(argv):
    if len(argv) != 2:
        print("Usage: %s /path/to/clang/lib/Lex/UnicodeCharSets.h" % (argv[0]))
        sys.exit(-1)
    srcf = argv[1]
    with open(srcf, 'rb') as fp:
        srcbuf = fp.read().decode('utf-8')
        if srcbuf.find('Patched by ICPP') > 0:
            print("The file %s has already been patched." % (srcf))
            sys.exit(0)
    with open(srcf, 'w') as fp:
        # remove all the non ascii characters in this file
        asciisrc = ''.join(filter(lambda x: x in string.printable, srcbuf))
        fp.write(icpp_patch_magic)
        fp.write(asciisrc)

if __name__ == "__main__":
    patch_llvm_unicode(sys.argv)
