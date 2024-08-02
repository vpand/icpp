# User Manual of iopad

## Summarization
IOPAD is a local C++ source compiler driver, an object launch pad and a REPL for the remote icpp-gadget.

## How it works
When running this client side tool, it'll connect to IP:PORT, compile the input C++ source using icpp to an object file and then send it to the remote icpp-server/icpp-gadget-process to execute. It's useful for remote processes and Linux/Android/iOS systems.

The building type of object file is automatically determined by the remote system and architecture sent from the server. If the remote system and architecture are the same as local's, you can use the integrated C++ standard module with the import directive, otherwise you should use the old C style #include.

If the icpp-gadget is running on an Android device, the --ndk argument should be applied when the ndk-build isn't in the system PATH environment, otherwise you can only use a small set of standard C headers in your input source file.

If you want to redirect the log messages to the iopad side, you should use the following apis to log messages, otherwise they'll be printed directly in the icpp-gadget side:
 * std::puts;
 * std::printf;
 * icpp::prints;

## Usage
```sh
vpand@MacBook-Pro icpp % iopad -h
OVERVIEW: ICPP, Interpreting C++, running C++ in anywhere like a script.
  IObject Launch Pad Tool built with ICPP v0.1.0.255
USAGE: iopad [options]

OPTIONS:

ICPP Interpretable Object Launch Pad Options:

  --fire=<string>   - Fire the input source file to the connected remote icpp-gadget to execute it.
  --incdir=<string> - Specify the include directory for compilation, can be multiple.
  --ip=<string>     - Set the remote ip address of icpp-gadget.
  --ndk=<string>    - Set the Android NDK root path, default to the parent directory of the ndk-build in PATH.
  --port=<int>      - Set the connection port.
  --repl            - Enter into a REPL interactive shell to fire the input snippet code to the connected remote icpp-gadget to execute it.
```

## Examples
### Server
```sh
vpand@MacBook-Pro icpp % icpp-server 
Running icpp-server at port 24703...
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
