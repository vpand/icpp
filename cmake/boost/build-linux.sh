arch=$(uname -m)
echo Building boost for ${arch} linux...

CXXFLAGS="-nostdinc++ -nostdlib++ -fPIC -I${PWD}/../runtime/include/c++/v1" LDFLAGS="-L${PWD}/llvm/lib/${arch}-unknown-linux-gnu -lc++ -lc++abi -lunwind @${PWD}/../src/ld.txt" cmake -B boostbuild -G Ninja -DCMAKE_C_COMPILER=${PWD}/llvm/bin/clang -DCMAKE_CXX_COMPILER=${PWD}/llvm/bin/clang -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DCMAKE_BUILD_WITH_INSTALL_RPATH=ON ../third/boost
cmake --build boostbuild
cmake --install boostbuild --prefix ${PWD}/boost

rm boost/lib/*.a
rm -rf boost/lib/cmake
strip -x boost/lib/libboost*
