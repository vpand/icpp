'''
* Interpreting C++, executing the source and executable like a script */
* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
* This file is released under LGPL2.
  See LICENSE in root directory for more details
'''

import sys

icpp_patch_magic = "# Patched by ICPP to make boost to build like at the top source level. */\n"
split_magic = "include(BoostRoot)"

def patch_boost_cmake(argv):
    if len(argv) != 2:
        print("Usage: %s /path/to/boost/CMakeLists.txt" % (argv[0]))
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
        fp.write(
'''set(CMAKE_SOURCE_DIR_ORIG ${CMAKE_SOURCE_DIR})
set(CMAKE_SOURCE_DIR ${PROJECT_SOURCE_DIR})
%s
set(CMAKE_SOURCE_DIR ${CMAKE_SOURCE_DIR_ORIG})
%s''' % (split_magic, parts[1]))

if __name__ == "__main__":
    patch_boost_cmake(sys.argv)
