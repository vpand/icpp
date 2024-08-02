# User Manual of icpp-server

## Summarization
ICPP-SERVER is a remote server daemon which loads icpp-gadget as its C++ interpreter, waiting for iopad to send the interpretable object to execute. 

## How it works
When running this server side tool, it'll load the icpp-gadget interpreter library and listen at port 24703, waiting for iopad's connection and commands. It's useful for remote Linux/Android/iOS systems.

## Usage
```sh
vpand@MacBook-Pro icpp % icpp-server -h
OVERVIEW: ICPP, Interpreting C++, running C++ in anywhere like a script.
  Remote icpp-gadget server built with ICPP v0.1.0.255
USAGE: icpp-server [options]

OPTIONS:

ICPP Remote Gadget Server Options:

  --port=<int> - Set the listening port.
```

## Examples
```sh
vpand@MacBook-Pro icpp % icpp-server 
Running icpp-server at port 24703...
```
```sh
vpand@MacBook-Pro icpp % icpp-server --port=24802
Running icpp-server at port 24802...
```
