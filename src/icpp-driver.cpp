/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "llvm/ADT/ArrayRef.h"
#include "llvm/Support/LLVMDriver.h"

int clang_main(int argc, char **, const llvm::ToolContext &);

int iclang_main(int argc, const char **argv) {
  return clang_main(argc, const_cast<char **>(argv), {argv[0], nullptr, false});
}
