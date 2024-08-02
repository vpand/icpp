# User Manual of icpp-gadget

## Summarization
ICPP-GADGET is a remote memory resident daemon which may run inside an Android/iOS process, waiting for iopad to send the interpretable object to execute.

## How it works
Simply to say, icpp-gadget = icpp - clang. So it's smaller and suitable to run in any other environments. It can be loaded by any processes and then listens at port 24703 automatically by default, waiting for iopad to send the interpretable object to execute in the resident process.

## Examples
### Server
```c
// add this function to your test project
void __attribute__((constructor)) __init_icpp__(void) {
  // use the default installed path on iOS
  dlopen("/usr/local/lib/icpp-gadget.dylib", RTLD_NOW);
}
```

### Client
```sh
vpand@MacBook-Pro icpp % iopad --ip=192.168.31.103 --fire=printargv.cc 
argc=1, argv={ "printargv.cc", }
```
```cpp
vpand@MacBook-Pro icpp % iopad --ip=192.168.31.103 --repl                      
ICPP v0.1.0.255 IOPAD mode. Copyright (c) vpand.com.
Running C++ in anywhere like a script.
>>> import std
>>> std::puts("Hello icpp.")
Hello icpp.
```