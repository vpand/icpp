# User Manual of imod
## Summarization
IMOD is an icpp module package manager tool used to install, uninstall and show the third-party modules.

## How it works
### Home
This tool mainly works for the HOME/.icpp directory which it installs to, uninstalls from and lists the third-party icpp modules. The HOME in different system has different value as follows: * macOS/Linux/iOS: HOME = $HOME; * Windows: HOME = %userprofile%; * Android: HOME = /sdcard/Android;

### Configuration
When creating a new icpp module, you should give it a json configuration file to tell imod what to do. A general template json is as follows:
```json
{
  "name": "",
  "headers": [],
  "header-dirs": [],
  "sources": [],
  "binary-objs": [],
  "binary-libs": [],
  "include-dirs": [],
  "install-prefix": ""
}
```

 * **name**: the icpp module name;
 * **headers**: the export C/C++ headers which will be packed into this module;
 * **header-dirs**: the export C/C++ header directories which will be packed into this module;
 * **sources**: the module source files which will be compiled as objects and then be packed into this module;
 * **binary-objs**: the precompiled object files which will be packed into this module;
 * **binary-libs**: the dynamic shared libraries which will be packed into this module;
 * **include-dirs**: the temporary include directories used when compile the previous sources;
 * **install-prefix**: the install prefix of the binary-libs used when you want to keep the layout of packed libraries;

## Usage
```sh
vpand@MacBook-Pro icpp % imod -h                
OVERVIEW: ICPP, Interpreting C++, running C++ in anywhere like a script.
  IObject Module Manager Tool built with ICPP v0.1.0.255
USAGE: imod [options]

OPTIONS:

ICPP Module Manager Options:

  --create=<string>    - Create an icpp package from a json configuration file.
  --install=<string>   - Install an icpp package file.
  --list               - List all the installed modules.
  --uninstall=<string> - Uninstall an installed module.
```

## Examples
### Configuration
The working directory should be ICPP_ROOT/snippet when you are testing this configuration.
```json
{
  "name": "module-demo",
  "headers": ["module.h"],
  "header-dirs": [],
  "sources": ["module.cc", "main.cc"],
  "binary-objs": [],
  "binary-libs": [],
  "include-dirs": []
}
```
Another complicated demonstration configuration can be found at [icpp-qt](https://github.com/vpand/icpp-qt/blob/main/qt-osx.json).

### Create
```sh
vpand@MacBook-Pro snippet % imod --create=./module.json
 + Packing include/icpp/module-demo/module.h.
 + Packing lib/module-demo/module.o.
 + Packing lib/module-demo/main.o.
 | Built a new package with raw size: 2929.
 | Compressing the package buffer with brotli...
 | Successfully created ./module-demo-osx-arm64.icpp with compressed size: 1147.
```

### Install
```sh
vpand@MacBook-Pro snippet % imod --install=./module-demo-osx-arm64.icpp
 | Decompressing package buffer...
 | Installing module module-demo...
 | Installing include/icpp/module-demo/module.h...
 | Installing lib/module-demo/module.o...
 | Parsing the symbols of lib/module-demo/module.o...
 | Parsed 2 symbols in module.o.
 | Installing lib/module-demo/main.o...
 | Parsing the symbols of lib/module-demo/main.o...
 | Parsed 1 symbols in main.o.
 | Created /Users/geekneo/.icpp/lib/module-demo/symbol.hash.
 + Successfully installed module-demo.
```

### List
```sh
vpand@MacBook-Pro snippet % imod --list                                
Installed module:
 * module-demo
```

### Run
```sh
vpand@MacBook-Pro snippet % icpp module-demo Hello icpp module .
argc=5, argv={ "module-demo", "Hello", "icpp", "module", ".", }
```

### Uninstall
```sh
vpand@MacBook-Pro snippet % imod --uninstall=module-demo        
 | Uninstalled module module-demo.
```
