'''
* Interpreting C++, executing the source and executable like a script */
* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
* This file is released under LGPL2.
  See LICENSE in root directory for more details
'''

import sys

icpp_patch_magic = "# Patched by ICPP to link icpp as a shared library.\n"
split_magic = "    add_executable"

def patch_llvm_cmake(argv):
    if len(argv) != 2:
        print("Usage: %s /path/to/AddLLVM.cmake" % (argv[0]))
        sys.exit(-1)
    srcf = argv[1]
    with open(srcf, 'r') as fp:
        srcbuf = fp.read()
        if srcbuf.startswith(icpp_patch_magic):
            print("The file %s has already been patched." % (srcf))
            sys.exit(0)
    '''
  if( EXCLUDE_FROM_ALL )
    add_executable(${name} EXCLUDE_FROM_ALL ${ALL_FILES})
  else()
    add_executable(${name} ${ALL_FILES})
  endif()
    '''
    parts = srcbuf.split(split_magic)
    with open(srcf, 'w') as fp:
        # part0
        fp.write(icpp_patch_magic)
        fp.write(parts[0])
        # part1
        fp.write(
'''    if (${name} STREQUAL "icpp")
      add_library(${name} SHARED EXCLUDE_FROM_ALL ${ALL_FILES})
    else()
      add_executable(${name} EXCLUDE_FROM_ALL ${ALL_FILES})
    endif()
'''     )
        fp.write(parts[1][parts[1].find('\n')+1:len(parts[1])])
        # part2
        fp.write(
'''    if (${name} STREQUAL "icpp")
      add_library(${name} SHARED ${ALL_FILES})
    else()
      add_executable(${name} ${ALL_FILES})
    endif()
'''     )
        fp.write(parts[2][parts[2].find('\n')+1:len(parts[2])])
        print("The file %s has been patched." % (srcf))
        sys.exit(0)

if __name__ == "__main__":
    patch_llvm_cmake(sys.argv)
