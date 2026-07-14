# Visual ICPP in Cutter++
Making C++ script running in visual and debuggable mode, mainly for developer
who is interested in the ICPP Execution Engine.

[Cutter++](https://github.com/GeekNeo/CutterPlusPlus) is a plugin for [Cutter](https://github.com/rizinorg/cutter) that brings an interactive C++ REPL directly into your reverse engineering workflow.

We use it to load and drive `icppdbg` library to inspect the execution of ICPP script. It's specially useful for the ICPP Execution Engine debugging.

## Usage
### Load
Before loading the icppdbg library, we should run ICPP in debugger mode:
```json
{
  "vm_debugger": true,
  "uc_step_size": 1
}
```
Then we can load the running object of the C++ script into Cutter and type (change the ICPP_ROOT to your real path):
```c++
C++ >>> icpp::load_library("/ICPP_ROOT/build/cutter++/icppdbg.dll")
```
### Include
```c++
C++ >>> #include "/ICPP_ROOT/cutter++/icppdbg.h"
```
### Debug
```c++
C++ >>>
vi::connect(): connect to icpp debug server.
vi::disconnect(): disconnect to icpp debug server.
vi::pause(): pause current thread.
vi::run(): run current thread from pausing.
vi::stop(): stop running current script file.
vi::setbp(addr): set breakpoint at the specified address.
vi::delbp(addr): delete breakpoint at the specified address.
vi::readmem(addr, bytes, format): read memory at the specified address,
    the format can be: '1ix', '4ix', '8ix', 'str'.
vi::stepi(): step into 1 instruction.
vi::stepo(): step over 1 instruction.
vi::lsthread(): list all the running threads.
vi::lsobject(): list all the running objects.
vi::switchthread(tid): switch the debuggee thread.
```
