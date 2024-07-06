
'''
* Interpreting C++, executing the source and executable like a script */
* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
* Copyright (c) vpand.com 2024. This file is released under LGPL2.
  See LICENSE in root directory for more details
'''

import sys

icpp_patch_magic = "# Patched by ICPP to cmake correctly on Windows ARM64.\n"
split_magic = "    string(REGEX REPLACE "

def patch_unicorn_cmake(argv):
    if len(argv) != 2:
        print("Usage: %s /path/to/unicorn/CMakeLists.txt" % (argv[0]))
        sys.exit(-1)
    srcf = argv[1]
    with open(srcf, 'r') as fp:
        srcbuf = fp.read()
        if srcbuf.startswith(icpp_patch_magic):
            print("The file %s has already been patched." % (srcf))
            sys.exit(0)
    # patch to arm64 parameters
    srcbuf = srcbuf.replace('MSVC_FLAG  -D__x86_64__', 'MSVC_FLAG  -D__aarch64__ -Dasm=__asm__')
    srcbuf = srcbuf.replace('tcg/i386', 'tcg/aarch64')
    parts = srcbuf.split(split_magic)
    with open(srcf, 'w') as fp:
        # part0
        fp.write(icpp_patch_magic)
        fp.write(parts[0])
        # part1
        # comment out: string(REGEX REPLACE "[/-]M[TD]d?" "" CMAKE_C_FLAGS ${CMAKE_C_FLAGS})
        fp.write('#')
        fp.write(split_magic)
        # disable to add the asm file
        fp.write(parts[1].replace('if(CMAKE_SIZEOF_VOID_P EQUAL 8)', 'if(CMAKE_SIZEOF_VOID_P EQUAL 88)'))
        print("The file %s has been patched." % (srcf))
        sys.exit(0)

if __name__ == "__main__":
    patch_unicorn_cmake(sys.argv)
