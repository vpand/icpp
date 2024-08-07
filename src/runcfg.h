/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#pragma once

namespace icpp {

// running config for advanced user from a json configuration file,
// it can be used to control the behaviour of icpp execute engine,
// i.e.: interpreter's stack size, step count, step debugging, etc.
class RunConfig {
public:
  static RunConfig *inst(const char *argv0 = nullptr,
                         const char *cfg = nullptr);

  RunConfig(const char *cfg);
  ~RunConfig();

  int stackSize();

  // how many instructions should be executed each time
  int stepSize();

  bool hasDebugger();

  // the main program
  const char *program;

  // whether in repl mode
  static bool repl;

  // whether in gadget mode
  static bool gadget;

  // printf/puts pointer
  static int (*printf)(const char *, ...);
  static int (*puts)(const char *);

private:
  // default stack size 1MB
  int stack_size_ = 1024 * 1024;
  // default step size -1(the max value as interpreter can)
  int step_size_ = -1;
  // default debugger status off
  bool has_debugger_ = false;
};

} // namespace icpp
