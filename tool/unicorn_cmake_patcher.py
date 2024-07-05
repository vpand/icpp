'''
* Interpreting C++, executing the source and executable like a script */
* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
* Copyright (c) vpand.com 2024. This file is released under LGPL2.
  See LICENSE in root directory for more details
'''

import sys

icpp_patch_magic = "# Patched by ICPP to cmake correctly on Windows.\n"
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
    parts = srcbuf.split(split_magic)
    with open(srcf, 'w') as fp:
        # part0
        fp.write(icpp_patch_magic)
        fp.write(parts[0])
        # part1
        # comment out: string(REGEX REPLACE "[/-]M[TD]d?" "" CMAKE_C_FLAGS ${CMAKE_C_FLAGS})
        fp.write('#')
        fp.write(split_magic)
        fp.write(parts[1])
        print("The file %s has been patched." % (srcf))
        sys.exit(0)

if __name__ == "__main__":
    patch_unicorn_cmake(sys.argv)
