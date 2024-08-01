# User Manual of icpp
## Summarization
ICPP is a local C++ source compiler, a LLVM code style formatter, an interpreter and a REPL used to interpret C++ directly.

## How it works

## Usage
```sh
vpand@MacBook-Pro icpp % icpp -h              
OVERVIEW: ICPP v0.1.0.255 based on Unicorn and Clang/LLVM.
  Interpreting C++, running C++ in anywhere like a script.

USAGE: icpp [options] exec0 [exec1 ...] [[--] args]
OPTIONS:
  -v, -version: print icpp version.
  --version: print icpp and clang version.
  -h, -help: print icpp help list.
  --help: print icpp and clang help list.
  -f: format the input source file as LLVM code style.
  -O0, -O1, -O2, -O3, -Os, -Oz: optimization level passed to clang, default to -O2.
  -I/path/to/include: header include directory passed to clang.
  -L/path/to/library: library search directory passed to icpp interpreter.
  -lname: full name of the dependent library file passed to icpp interpreter, e.g.: liba.dylib, liba.so, a.dll.
  -F/path/to/framework: framework search directory passed to icpp interpreter.
  -fname: framework name of the dependent library file passed to icpp interpreter.
  -p/path/to/json: professional json configuration file for trace/profile/plugin/etc..
FILES: input file can be C++ source code(.c/.cc/.cpp/.cxx), MachO/ELF/PE executable.
ARGS: arguments passed to the main entry function of the input files.

Run a C++ source file, e.g.:
  icpp helloworld.cc
  icpp helloworld.cc -- Hello World (i.e.: argc=3, argv[]={"helloworld.cc", "Hello", "World"})
  icpp -O3 helloworld.cc
  icpp -O0 -p/path/to/profile.json helloworld.cc
  icpp -I/qt/include -L/qt/lib -llibQtCore.so hellowrold.cc
  icpp -I/qt/include -L/qt/lib -lQtCore.dll hellowrold.cc
  icpp -I/qt/include -F/qt/framework -fQtCore hellowrold.cc

Run an executable, e.g.:
  icpp -p/path/to/trace.json helloworld.exe
  icpp -p/path/to/profile.json helloworld

Run an installed module, e.g.:
  icpp helloworld
  icpp helloworld -- hello world

Run an C++ expression, e.g:
  icpp "puts(std::format(\"{:x}\", 88888888).data())"
```

## REPL

### Usage

### Examples

## Interpreter

### Usage

### Examples

## Compiler

### Usage

### Examples

## Formatter

### Usage

### Examples
