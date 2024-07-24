'''
* Interpreting C++, executing the source and executable like a script */
* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
* Copyright (c) vpand.com 2024. This file is released under LGPL2.
  See LICENSE in root directory for more details
'''

import sys

icpp_patch_magic = "/* Patched by ICPP to avoid finding vctool multiple times. */\n"

def patch_vctool_find(argv):
    if len(argv) != 2:
        print("Usage: %s /path/to/llvm/lib/WindowsDriver/MSVCPaths.cpp" % (argv[0]))
        sys.exit(-1)
    srcf = argv[1]
    with open(srcf, 'r') as fp:
        srcbuf = fp.read()
        if srcbuf.startswith(icpp_patch_magic):
            print("The file %s has already been patched." % (srcf))
            sys.exit(0)
    
    split0 = "// FIXME: This really should be done once in the top-level program's main"
    split1 = "VSLayout = ToolsetLayout::VS2017OrNewer;"
    parts0 = srcbuf.split(split0)
    parts1 = parts0[1].split(split1)
    with open(srcf, 'w') as fp:
        fp.write(icpp_patch_magic)
        fp.write(parts0[0])
        fp.write('''
  // as icpp may compile multiple source files, and multiple calling this
  // function will lead to a crash, so save these variables to use them 
  // next time directly.
  static std::string VS_Path;
  static ToolsetLayout VS_Layout;
  if (VS_Path.size()) {
    VFS.status(VS_Path);
    Path = VS_Path;
    VSLayout = VS_Layout;
    return true;
  }
        ''')
        fp.write(split0)
        fp.write(parts1[0])
        fp.write(split1)
        fp.write('''
  VS_Path = Path;
  VS_Layout = VSLayout;
        ''')
        fp.write(parts1[1])
        print("The file %s has been patched." % (srcf))
        sys.exit(0)

if __name__ == "__main__":
    patch_vctool_find(sys.argv)
