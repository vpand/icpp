/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "llvm/ADT/ArrayRef.h"
#include "llvm/Support/InitLLVM.h"
#include "llvm/Support/LLVMDriver.h"

int clang_main(int argc, char **, const llvm::ToolContext &);
int icpp_main(int argc, char **);

int main(int argc, char **argv) {
  /*
  A none zero iret indicates the argc/argv are clang arguments.
  Otherwise they're icpp arguments, so just return directly.
  */
  int iret = icpp_main(argc, argv);
  if (!iret)
    return 0;

  llvm::InitLLVM X(argc, argv);
  return clang_main(argc, argv, {argv[0], nullptr, false});
}
