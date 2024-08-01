# User Manual of iopad

## Summarization
IOPAD is a local C++ source compiler driver, an object launch pad and a REPL for the remote icpp-gadget.

## How it works

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
