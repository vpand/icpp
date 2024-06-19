/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "exec.h"
#include "object.h"
#include "utils.h"

#include <llvm/ADT/Twine.h>
#include <llvm/BinaryFormat/Magic.h>
#include <unicorn/unicorn.h>

namespace icpp {

static void exec_with_object(std::unique_ptr<Object> object,
                             const std::vector<std::string> &deps,
                             const char *procfg,
                             const std::vector<const char *> &iargs) {}

void exec_main(std::string_view path, const std::vector<std::string> &deps,
               const char *procfg, int iargc, char **iargv) {
  llvm::file_magic magic;
  auto err = llvm::identify_magic(llvm::Twine(path), magic);
  if (err) {
    std::cout << "Failed to identify the file type of '" << path
              << "': " << err.message() << std::endl;
    return;
  }

  std::unique_ptr<Object> object;
  using fm = llvm::file_magic;
  switch (magic) {
  case fm::macho_object:
    object = std::make_unique<MachORelocObject>(path);
    break;
  case fm::macho_executable:
    object = std::make_unique<MachOExeObject>(path);
    break;
  case fm::elf_relocatable:
    object = std::make_unique<ELFRelocObject>(path);
    break;
  case fm::elf_executable:
    object = std::make_unique<ELFExeObject>(path);
    break;
  case fm::coff_object:
    object = std::make_unique<COFFRelocObject>(path);
    break;
  case fm::pecoff_executable:
    object = std::make_unique<COFFExeObject>(path);
    break;
  default:
    std::cout << "Unsupported input file type " << magic
              << ", currently supported file type includes "
                 "MachO/ELF/PE-Object/Executable."
              << std::endl;
    return;
  }
  if (!object->valid()) {
    std::cout << "Unsupported input file type " << magic
              << ", currently supported file type includes "
                 "MachO/ELF/PE-Object/Executable-X86_64/AArch64."
              << std::endl;
  }

  // construct arguments passed to the main entry of the input file
  std::vector<const char *> iargs;
  iargs.push_back(path.data());
  for (int i = 0; i < iargc; i++)
    iargs.push_back(iargv[i]);
  exec_with_object(std::move(object), deps, procfg, iargs);
}

} // namespace icpp
