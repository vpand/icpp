/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under GPLv2.
   See LICENSE in root directory for more details
*/

/*
Visual ICPP makes C++ script running in visual and debuggable mode.

[Cutter++] C++ >>>
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
*/

#pragma once

namespace vi {

void connect();
void disconnect();
void pause();
void run();
void stop();
void setbp(uint64_t addr);
void delbp(uint64_t addr);
void readmem(uint64_t addr, uint32_t bytes, const char *format);
void stepi();
void stepo();
void lsthread();
void lsobject();
void switchthread(uint64_t tid);

} // namespace vi
