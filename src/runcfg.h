/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#pragma once

namespace icpp {

class RunConfig {
public:
  RunConfig(const char *cfg);
  ~RunConfig();

  int stackSize();

  // how many instructions should be executed each time
  int stepSize();
};

} // namespace icpp
