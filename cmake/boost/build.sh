cmake -B boostbuild -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON ../third/boost
cmake --build boostbuild
cmake --install boostbuild --prefix $PWD/boost
rm boost/lib/*.a
rm -rf boost/lib/cmake
strip -x boost/lib/libboost*
