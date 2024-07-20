import os

def main():
    thisdir = os.path.abspath(os.path.dirname(__file__))
    pwd = os.path.abspath(os.getcwd())
    cmds = [
        'cmake -DCMAKE_CXX_FLAGS="-I%s/../runtime/include/c++/v1 /EHsc" -DCMAKE_SHARED_LINKER_FLAGS="%s/libcxx/Release/lib/Release/c++.lib %s/demangle/build/demangle.lib" -B boostbuild -G Ninja -DCMAKE_C_COMPILER=clang-cl -DCMAKE_CXX_COMPILER=clang-cl -DCMAKE_MT=llvm-mt -DCMAKE_ASM_MASM_COMPILE_OBJECT=armasm64 -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DCMAKE_BUILD_WITH_INSTALL_RPATH=ON ../third/boost' % (pwd, pwd, thisdir),
        'cmake --build boostbuild',
        'cmake --install boostbuild --prefix %s/boost' % (pwd)]
    for cmd in cmds:
        if os.system(cmd):
            break

if __name__ == '__main__':
    main()
