/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "llvm/ADT/ArrayRef.h"
#include "llvm/Support/InitLLVM.h"
#include "llvm/Support/LLVMDriver.h"

#if defined(_WIN32) || defined(_WIN64)
#define __ICPP_EXPORT__ __declspec(dllexport)
#else
#define __ICPP_EXPORT__ __attribute__((visibility("default")))
#endif // end of _WIN

int clang_main(int argc, char **, const llvm::ToolContext &);

int icli_main(int argc, char **);

extern "C" __ICPP_EXPORT__ int icpp_main(int argc, char **argv) {
  /*
  A none zero iret indicates the argc/argv are clang arguments.
  Otherwise they're icpp arguments, so just return directly.
  */
  int iret = icli_main(argc, argv);
  if (!iret)
    return 0;

  llvm::InitLLVM X(argc, argv);
  return clang_main(argc, argv, {argv[0], nullptr, false});
}
