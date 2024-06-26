/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

// modified from llvm-objdump

//===-- llvm-objdump.cpp - Object file dumping utility for llvm -----------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This program is a utility that works like binutils "objdump", that is, it
// dumps out a plethora of information about an object file depending on the
// flags.
//
// The flags and output of this program should be near identical to those of
// binutils objdump.
//
//===----------------------------------------------------------------------===//

#include "SourcePrinter.h"
#include "llvm-objdump.h"
#include "loader.h"
#include "log.h"
#include "object.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/SetOperations.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/ADT/Twine.h"
#include "llvm/BinaryFormat/COFF.h"
#include "llvm/BinaryFormat/ELF.h"
#include "llvm/BinaryFormat/MachO.h"
#include "llvm/BinaryFormat/Wasm.h"
#include "llvm/DebugInfo/BTF/BTFParser.h"
#include "llvm/DebugInfo/DWARF/DWARFContext.h"
#include "llvm/DebugInfo/Symbolize/SymbolizableModule.h"
#include "llvm/DebugInfo/Symbolize/Symbolize.h"
#include "llvm/Debuginfod/BuildIDFetcher.h"
#include "llvm/Debuginfod/Debuginfod.h"
#include "llvm/Debuginfod/HTTPClient.h"
#include "llvm/Demangle/Demangle.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCDisassembler/MCDisassembler.h"
#include "llvm/MC/MCDisassembler/MCRelocationInfo.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCInstPrinter.h"
#include "llvm/MC/MCInstrAnalysis.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCObjectFileInfo.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCTargetOptions.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Object/Archive.h"
#include "llvm/Object/BuildID.h"
#include "llvm/Object/COFF.h"
#include "llvm/Object/COFFImportFile.h"
#include "llvm/Object/ELFObjectFile.h"
#include "llvm/Object/ELFTypes.h"
#include "llvm/Object/FaultMapParser.h"
#include "llvm/Object/MachO.h"
#include "llvm/Object/MachOUniversal.h"
#include "llvm/Object/ObjectFile.h"
#include "llvm/Object/OffloadBinary.h"
#include "llvm/Object/Wasm.h"
#include "llvm/Option/Arg.h"
#include "llvm/Option/ArgList.h"
#include "llvm/Option/Option.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/Errc.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Format.h"
#include "llvm/Support/FormatVariadic.h"
#include "llvm/Support/GraphWriter.h"
#include "llvm/Support/LLVMDriver.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/StringSaver.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/WithColor.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/TargetParser/Host.h"
#include "llvm/TargetParser/Triple.h"
#include <algorithm>
#include <cctype>
#include <cstring>
#include <optional>
#include <set>
#include <system_error>
#include <unicorn/unicorn.h>
#include <unordered_map>
#include <utility>

using namespace llvm;
using namespace llvm::object;
using namespace llvm::objdump;
using namespace llvm::opt;

constexpr const char *ToolName = "icpp";

bool objdump::ArchiveHeaders = false;
bool objdump::Demangle = true;
bool objdump::Disassemble = true;
bool objdump::DisassembleAll = false;
bool objdump::SymbolDescription = true;
bool objdump::TracebackTable = true;
bool objdump::SectionContents = false;
bool objdump::PrintLines = true;
bool objdump::ShowRawInsn = true;
bool objdump::LeadingAddr = true;
bool objdump::Relocations = true;
bool objdump::PrintImmHex = true;
bool objdump::PrivateHeaders = true;
bool objdump::SectionHeaders = true;
bool objdump::PrintSource = true;
bool objdump::SymbolTable = true;
bool objdump::UnwindInfo = true;
std::string objdump::Prefix;
uint32_t objdump::PrefixStrip;
int objdump::DbgIndent = 52;
DebugVarsFormat objdump::DbgVariables = DVDisabled;

void objdump::reportWarning(const Twine &Message, StringRef File) {
  // Output order between errs() and outs() matters especially for archive
  // files where the output is per member object.
  outs().flush();
  WithColor::warning(errs(), ToolName)
      << "'" << File << "': " << Message << "\n";
}

[[noreturn]] void objdump::reportError(StringRef File, const Twine &Message) {
  outs().flush();
  WithColor::error(errs(), ToolName) << "'" << File << "': " << Message << "\n";
  exit(1);
}

[[noreturn]] void objdump::reportError(Error E, StringRef FileName,
                                       StringRef ArchiveName,
                                       StringRef ArchitectureName) {
  assert(E);
  outs().flush();
  WithColor::error(errs(), ToolName);
  if (ArchiveName != "")
    errs() << ArchiveName << "(" << FileName << ")";
  else
    errs() << "'" << FileName << "'";
  if (!ArchitectureName.empty())
    errs() << " (for architecture " << ArchitectureName << ")";
  errs() << ": ";
  logAllUnhandledErrors(std::move(E), errs());
  exit(1);
}

/// Get the column at which we want to start printing the instruction
/// disassembly, taking into account anything which appears to the left of it.
unsigned objdump::getInstStartColumn(const MCSubtargetInfo &STI) {
  return !ShowRawInsn ? 16 : STI.getTargetTriple().isX86() ? 40 : 24;
}

namespace icpp {

static const char *archName(const ObjectFile *Obj) {
  switch (Obj->getArch()) {
  case Triple::aarch64:
    return "aarch64";
  case Triple::x86_64:
    return "x86-64";
  default:
    return "";
  }
}

static const Target *getTarget(const ObjectFile *Obj, std::string &TripleName) {
  static bool init_llvm = false;
  if (!init_llvm) {
    init_llvm = true;
    // Initialize All target infos
#define init_target(name)                                                      \
  LLVMInitialize##name##Target();                                              \
  LLVMInitialize##name##TargetMC();                                            \
  LLVMInitialize##name##TargetInfo();                                          \
  LLVMInitialize##name##AsmPrinter();                                          \
  LLVMInitialize##name##AsmParser();                                           \
  LLVMInitialize##name##Disassembler();
    init_target(AArch64);
    init_target(X86);
  }

  // Figure out the target triple.
  Triple TheTriple("unknown-unknown-unknown");
  if (TripleName.empty()) {
    TheTriple = Obj->makeTriple();
  } else {
    TheTriple.setTriple(Triple::normalize(TripleName));
    auto Arch = Obj->getArch();
    if (Arch == Triple::arm || Arch == Triple::armeb)
      Obj->setARMSubArch(TheTriple);
  }

  // Get the target specific parser.
  std::string Error;
  const Target *TheTarget =
      TargetRegistry::lookupTarget(archName(Obj), TheTriple, Error);
  if (!TheTarget)
    reportError(Obj->getFileName(), "can't find target: " + Error);

  // Update the triple name and return the found target.
  TripleName = TheTriple.getTriple();
  return TheTarget;
}

/// Indicates whether this relocation should hidden when listing
/// relocations, usually because it is the trailing part of a multipart
/// relocation that will be printed as part of the leading relocation.
static bool getHidden(RelocationRef RelRef) {
  auto *MachO = dyn_cast<MachOObjectFile>(RelRef.getObject());
  if (!MachO)
    return false;

  unsigned Arch = MachO->getArch();
  DataRefImpl Rel = RelRef.getRawDataRefImpl();
  uint64_t Type = MachO->getRelocationType(Rel);

  // On arches that use the generic relocations, GENERIC_RELOC_PAIR
  // is always hidden.
  if (Arch == Triple::x86 || Arch == Triple::arm || Arch == Triple::ppc)
    return Type == MachO::GENERIC_RELOC_PAIR;

  if (Arch == Triple::x86_64) {
    // On x86_64, X86_64_RELOC_UNSIGNED is hidden only when it follows
    // an X86_64_RELOC_SUBTRACTOR.
    if (Type == MachO::X86_64_RELOC_UNSIGNED && Rel.d.a > 0) {
      DataRefImpl RelPrev = Rel;
      RelPrev.d.a--;
      uint64_t PrevType = MachO->getRelocationType(RelPrev);
      if (PrevType == MachO::X86_64_RELOC_SUBTRACTOR)
        return true;
    }
  }

  return false;
}

class DisassemblerTarget {
public:
  const Target *TheTarget;
  std::unique_ptr<const MCSubtargetInfo> SubtargetInfo;
  std::shared_ptr<MCContext> Context;
  std::unique_ptr<MCDisassembler> DisAsm;
  std::shared_ptr<MCInstrAnalysis> InstrAnalysis;
  std::shared_ptr<MCInstPrinter> InstPrinter;

  DisassemblerTarget(const Target *TheTarget, ObjectFile &Obj,
                     StringRef TripleName, StringRef MCPU,
                     SubtargetFeatures &Features);
  DisassemblerTarget(DisassemblerTarget &Other, StringRef TripleName,
                     StringRef MCPU, SubtargetFeatures &Features);

private:
  MCTargetOptions Options;
  std::shared_ptr<const MCRegisterInfo> RegisterInfo;
  std::shared_ptr<const MCAsmInfo> AsmInfo;
  std::shared_ptr<const MCInstrInfo> InstrInfo;
  std::shared_ptr<MCObjectFileInfo> ObjectFileInfo;
};

DisassemblerTarget::DisassemblerTarget(const Target *TheTarget, ObjectFile &Obj,
                                       StringRef TripleName, StringRef MCPU,
                                       SubtargetFeatures &Features)
    : TheTarget(TheTarget),
      RegisterInfo(TheTarget->createMCRegInfo(TripleName)) {
  if (!RegisterInfo)
    reportError(Obj.getFileName(), "no register info for target " + TripleName);

  // Set up disassembler.
  AsmInfo.reset(TheTarget->createMCAsmInfo(*RegisterInfo, TripleName, Options));
  if (!AsmInfo)
    reportError(Obj.getFileName(), "no assembly info for target " + TripleName);

  SubtargetInfo.reset(
      TheTarget->createMCSubtargetInfo(TripleName, MCPU, Features.getString()));
  if (!SubtargetInfo)
    reportError(Obj.getFileName(),
                "no subtarget info for target " + TripleName);
  InstrInfo.reset(TheTarget->createMCInstrInfo());
  if (!InstrInfo)
    reportError(Obj.getFileName(),
                "no instruction info for target " + TripleName);
  Context =
      std::make_shared<MCContext>(Triple(TripleName), AsmInfo.get(),
                                  RegisterInfo.get(), SubtargetInfo.get());

  // FIXME: for now initialize MCObjectFileInfo with default values
  ObjectFileInfo.reset(
      TheTarget->createMCObjectFileInfo(*Context, /*PIC=*/false));
  Context->setObjectFileInfo(ObjectFileInfo.get());

  DisAsm.reset(TheTarget->createMCDisassembler(*SubtargetInfo, *Context));
  if (!DisAsm)
    reportError(Obj.getFileName(), "no disassembler for target " + TripleName);

  if (auto *ELFObj = dyn_cast<ELFObjectFileBase>(&Obj))
    DisAsm->setABIVersion(ELFObj->getEIdentABIVersion());

  InstrAnalysis.reset(TheTarget->createMCInstrAnalysis(InstrInfo.get()));

  int AsmPrinterVariant = AsmInfo->getAssemblerDialect();
  InstPrinter.reset(TheTarget->createMCInstPrinter(Triple(TripleName),
                                                   AsmPrinterVariant, *AsmInfo,
                                                   *InstrInfo, *RegisterInfo));
  if (!InstPrinter)
    reportError(Obj.getFileName(),
                "no instruction printer for target " + TripleName);
  InstPrinter->setPrintImmHex(PrintImmHex);
  InstPrinter->setPrintBranchImmAsAddress(true);
  InstPrinter->setMCInstrAnalysis(InstrAnalysis.get());
}

DisassemblerTarget::DisassemblerTarget(DisassemblerTarget &Other,
                                       StringRef TripleName, StringRef MCPU,
                                       SubtargetFeatures &Features)
    : TheTarget(Other.TheTarget),
      SubtargetInfo(TheTarget->createMCSubtargetInfo(TripleName, MCPU,
                                                     Features.getString())),
      Context(Other.Context),
      DisAsm(TheTarget->createMCDisassembler(*SubtargetInfo, *Context)),
      InstrAnalysis(Other.InstrAnalysis), InstPrinter(Other.InstPrinter),
      RegisterInfo(Other.RegisterInfo), AsmInfo(Other.AsmInfo),
      InstrInfo(Other.InstrInfo), ObjectFileInfo(Other.ObjectFileInfo) {}

void ObjectDisassembler::init(CObjectFile *Obj, std::string_view Triple) {
  std::string TripleName(Triple);
  const Target *TheTarget = getTarget(Obj, TripleName);
  std::string MCPU;
  std::vector<std::string> MAttrs;

  // Package up features to be passed to target/subtarget
  Expected<SubtargetFeatures> FeaturesValue = Obj->getFeatures();
  if (!FeaturesValue)
    reportError(FeaturesValue.takeError(), Obj->getFileName());
  SubtargetFeatures Features = *FeaturesValue;
  if (!MAttrs.empty()) {
    for (unsigned I = 0; I != MAttrs.size(); ++I)
      Features.AddFeature(MAttrs[I]);
  } else if (MCPU.empty() && Obj->getArch() == llvm::Triple::aarch64) {
    Features.AddFeature("+all");
  }

  if (MCPU.empty())
    MCPU = Obj->tryGetCPUName().value_or("").str();

  DT = new DisassemblerTarget(TheTarget, *Obj, TripleName, MCPU, Features);
  SP = new SourcePrinter(Obj, TheTarget->getName());
}

ObjectDisassembler::~ObjectDisassembler() {
  delete DT;
  delete SP;
}

std::string Object::sourceInfo(uint64_t vm) {
  uint64_t sindex = -1;
  uint64_t saddr = 0;
  for (auto &s : ofile_->sections()) {
    auto expContent = s.getContents();
    if (!expContent)
      continue;
    auto start = reinterpret_cast<uint64_t>(expContent->data());
    if (start <= vm && vm < start + s.getSize()) {
      sindex = s.getIndex();
      saddr = s.getAddress() + vm - start;
      break;
    }
  }
  if (sindex == -1)
    return "";

  std::string Output;
  raw_string_ostream OS(Output);
  formatted_raw_ostream FOS(OS);
  auto SectAddr = object::SectionedAddress{saddr, sindex};
  LiveVariablePrinter LVP(*odiser_.DT->Context->getRegisterInfo(),
                          *odiser_.DT->SubtargetInfo);
  odiser_.SP->printSourceLine(FOS, SectAddr, ofile_->getFileName(), LVP);
  FOS.flush();
  return Output;
}

#define GET_REGINFO_ENUM
#define GET_INSTRINFO_ENUM
#include "llvm/../../lib/Target/AArch64/AArch64GenInstrInfo.inc"
#include "llvm/../../lib/Target/AArch64/AArch64GenRegisterInfo.inc"

static uint16_t llvm2ucRegisterAArch64(unsigned reg) {
  namespace INSN = llvm::AArch64;

  // x
  if (INSN::X0 <= reg && reg <= INSN::X28)
    return UC_ARM64_REG_X0 + reg - INSN::X0;
  if (INSN::FP == reg)
    return UC_ARM64_REG_FP;
  if (INSN::LR == reg)
    return UC_ARM64_REG_LR;
  if (INSN::SP == reg)
    return UC_ARM64_REG_SP;
  // w
  if (INSN::W0 <= reg && reg <= INSN::W30)
    return UC_ARM64_REG_W0 + reg - INSN::W0;
  // s
  if (INSN::S0 <= reg && reg <= INSN::S31)
    return UC_ARM64_REG_S0 + reg - INSN::S0;
  // d
  if (INSN::D0 <= reg && reg <= INSN::D31)
    return UC_ARM64_REG_D0 + reg - INSN::D0;
  // b
  if (INSN::B0 <= reg && reg <= INSN::B31)
    return UC_ARM64_REG_B0 + reg - INSN::B0;
  // h
  if (INSN::H0 <= reg && reg <= INSN::H31)
    return UC_ARM64_REG_H0 + reg - INSN::H0;
  // q
  if (INSN::Q0 <= reg && reg <= INSN::Q31)
    return UC_ARM64_REG_Q0 + reg - INSN::Q0;

  log_print(Runtime, "Unknown llvm instruction register operand type: {}.",
            reg);
  abort();
}

static void parseInstAArch64(const MCInst &inst, uint64_t opcptr,
                             std::map<std::string, std::string> &decinfo,
                             InsnInfo &iinfo) {
  namespace INSN = llvm::AArch64;
  switch (inst.getOpcode()) {
  case INSN::BRK:
    iinfo.type = INSN_ABORT;
    break;
  case INSN::TBZW:
  case INSN::TBZX:
  case INSN::TBNZW:
  case INSN::TBNZX:
  case INSN::CBZW:
  case INSN::CBZX:
  case INSN::CBNZW:
  case INSN::CBNZX:
  case INSN::Bcc:
    iinfo.type = INSN_CONDJUMP;
    break;
  case INSN::RET:
    iinfo.type = INSN_ARM64_RETURN;
    break;
  case INSN::B:
    iinfo.type = INSN_ARM64_JUMP;
    break;
  case INSN::BR:
    iinfo.type = INSN_ARM64_JUMPREG;
    break;
  case INSN::BL:
    iinfo.type = INSN_ARM64_CALL;
    break;
  case INSN::BLR:
    iinfo.type = INSN_ARM64_CALLREG;
    break;
  case INSN::SVC:
    iinfo.type = INSN_ARM64_SYSCALL;
    break;
  case INSN::ADR:
    iinfo.type = INSN_ARM64_ADR;
    break;
  case INSN::ADRP:
    iinfo.type = INSN_ARM64_ADRP;
    break;
  case INSN::LDRSWl:
    iinfo.type = INSN_ARM64_LDRSWL;
    break;
  case INSN::LDRWl:
    iinfo.type = INSN_ARM64_LDRWL;
    break;
  case INSN::LDRXl:
    iinfo.type = INSN_ARM64_LDRXL;
    break;
  case INSN::LDRSl:
    iinfo.type = INSN_ARM64_LDRSL;
    break;
  case INSN::LDRDl:
    iinfo.type = INSN_ARM64_LDRDL;
    break;
  case INSN::LDRQl:
    iinfo.type = INSN_ARM64_LDRQL;
    break;
  default:
    iinfo.type = INSN_HARDWARE;
    break;
  }
}

#define GET_REGINFO_ENUM
#define GET_INSTRINFO_ENUM
#include "llvm/../../lib/Target/X86/X86GenInstrInfo.inc"
#include "llvm/../../lib/Target/X86/X86GenRegisterInfo.inc"

static uint16_t llvm2ucRegisterX64(unsigned reg) {
  namespace INSN = llvm::X86;

  if (INSN::AH == reg)
    return UC_X86_REG_AH;
  if (INSN::AL == reg)
    return UC_X86_REG_AL;
  if (INSN::AX == reg)
    return UC_X86_REG_AX;
  if (INSN::BH == reg)
    return UC_X86_REG_BH;
  if (INSN::BL == reg)
    return UC_X86_REG_BL;
  if (INSN::BP == reg)
    return UC_X86_REG_BP;
  if (INSN::BPL == reg)
    return UC_X86_REG_BPL;
  if (INSN::BX == reg)
    return UC_X86_REG_BX;
  if (INSN::CH == reg)
    return UC_X86_REG_CH;
  if (INSN::CL == reg)
    return UC_X86_REG_CL;
  if (INSN::CS == reg)
    return UC_X86_REG_CS;
  if (INSN::CX == reg)
    return UC_X86_REG_CX;
  if (INSN::DH == reg)
    return UC_X86_REG_DH;
  if (INSN::DI == reg)
    return UC_X86_REG_DI;
  if (INSN::DIL == reg)
    return UC_X86_REG_DIL;
  if (INSN::DL == reg)
    return UC_X86_REG_DL;
  if (INSN::DS == reg)
    return UC_X86_REG_DS;
  if (INSN::DX == reg)
    return UC_X86_REG_DX;
  if (INSN::EAX == reg)
    return UC_X86_REG_EAX;
  if (INSN::EBP == reg)
    return UC_X86_REG_EBP;
  if (INSN::EBX == reg)
    return UC_X86_REG_EBX;
  if (INSN::ECX == reg)
    return UC_X86_REG_ECX;
  if (INSN::EDI == reg)
    return UC_X86_REG_EDI;
  if (INSN::EDX == reg)
    return UC_X86_REG_EDX;
  if (INSN::EFLAGS == reg)
    return UC_X86_REG_EFLAGS;
  if (INSN::EIP == reg)
    return UC_X86_REG_EIP;
  if (INSN::ES == reg)
    return UC_X86_REG_ES;
  if (INSN::ESI == reg)
    return UC_X86_REG_ESI;
  if (INSN::ESP == reg)
    return UC_X86_REG_ESP;
  if (INSN::FPSW == reg)
    return UC_X86_REG_FPSW;
  if (INSN::FS == reg)
    return UC_X86_REG_FS;
  if (INSN::GS == reg)
    return UC_X86_REG_GS;
  if (INSN::IP == reg)
    return UC_X86_REG_IP;
  if (INSN::RAX == reg)
    return UC_X86_REG_RAX;
  if (INSN::RBP == reg)
    return UC_X86_REG_RBP;
  if (INSN::RBX == reg)
    return UC_X86_REG_RBX;
  if (INSN::RCX == reg)
    return UC_X86_REG_RCX;
  if (INSN::RDI == reg)
    return UC_X86_REG_RDI;
  if (INSN::RDX == reg)
    return UC_X86_REG_RDX;
  if (INSN::RIP == reg)
    return UC_X86_REG_RIP;
  if (INSN::RSI == reg)
    return UC_X86_REG_RSI;
  if (INSN::RSP == reg)
    return UC_X86_REG_RSP;
  if (INSN::SI == reg)
    return UC_X86_REG_SI;
  if (INSN::SIL == reg)
    return UC_X86_REG_SIL;
  if (INSN::SP == reg)
    return UC_X86_REG_SP;
  if (INSN::SPL == reg)
    return UC_X86_REG_SPL;
  if (INSN::SS == reg)
    return UC_X86_REG_SS;
  if (INSN::MM0 <= reg && reg <= INSN::MM7)
    return UC_X86_REG_MM0 + reg - INSN::MM0;
  if (INSN::R8 <= reg && reg <= INSN::R15)
    return UC_X86_REG_R8 + reg - INSN::R8;
  if (INSN::ST0 <= reg && reg <= INSN::ST7)
    return UC_X86_REG_ST0 + reg - INSN::ST0;
  if (INSN::XMM0 <= reg && reg <= INSN::XMM31)
    return UC_X86_REG_XMM0 + reg - INSN::XMM0;
  if (INSN::YMM0 <= reg && reg <= INSN::YMM31)
    return UC_X86_REG_YMM0 + reg - INSN::YMM0;
  if (INSN::ZMM0 <= reg && reg <= INSN::ZMM31)
    return UC_X86_REG_ZMM0 + reg - INSN::ZMM0;
  if (INSN::R8B == reg)
    return UC_X86_REG_R8B;
  if (INSN::R9B == reg)
    return UC_X86_REG_R9B;
  if (INSN::R10B == reg)
    return UC_X86_REG_R10B;
  if (INSN::R11B == reg)
    return UC_X86_REG_R11B;
  if (INSN::R12B == reg)
    return UC_X86_REG_R12B;
  if (INSN::R13B == reg)
    return UC_X86_REG_R13B;
  if (INSN::R14B == reg)
    return UC_X86_REG_R14B;
  if (INSN::R15B == reg)
    return UC_X86_REG_R15B;
  if (INSN::R8D == reg)
    return UC_X86_REG_R8D;
  if (INSN::R9D == reg)
    return UC_X86_REG_R9D;
  if (INSN::R10D == reg)
    return UC_X86_REG_R10D;
  if (INSN::R11D == reg)
    return UC_X86_REG_R11D;
  if (INSN::R12D == reg)
    return UC_X86_REG_R12D;
  if (INSN::R13D == reg)
    return UC_X86_REG_R13D;
  if (INSN::R14D == reg)
    return UC_X86_REG_R14D;
  if (INSN::R15D == reg)
    return UC_X86_REG_R15D;
  if (INSN::R8W == reg)
    return UC_X86_REG_R8W;
  if (INSN::R9W == reg)
    return UC_X86_REG_R9W;
  if (INSN::R10W == reg)
    return UC_X86_REG_R10W;
  if (INSN::R11W == reg)
    return UC_X86_REG_R11W;
  if (INSN::R12W == reg)
    return UC_X86_REG_R12W;
  if (INSN::R13W == reg)
    return UC_X86_REG_R13W;
  if (INSN::R14W == reg)
    return UC_X86_REG_R14W;
  if (INSN::R15W == reg)
    return UC_X86_REG_R15W;
  if (INSN::EFLAGS == reg)
    return UC_X86_REG_RFLAGS;

  log_print(Runtime, "Unknown llvm instruction register operand type: {}.",
            reg);
  abort();
}

static void parseInstX64(const MCInst &inst, uint64_t opcptr,
                         std::map<std::string, std::string> &decinfo,
                         InsnInfo &iinfo) {
  namespace INSN = llvm::X86;
  switch (inst.getOpcode()) {
  case INSN::INT:
  case INSN::INT3:
  case INSN::INTO:
  case INSN::TRAP:
    iinfo.type = INSN_ABORT;
    break;
  case INSN::JCC_1:
  case INSN::JCC_2:
  case INSN::JCC_4:
    iinfo.type = INSN_CONDJUMP;
    break;
  case INSN::RET:
  case INSN::RET16:
  case INSN::RET32:
  case INSN::RET64:
    iinfo.type = INSN_X64_RETURN;
    break;
  case INSN::SYSCALL:
    iinfo.type = INSN_X64_SYSCALL;
    break;
  case INSN::CALLpcrel16:
  case INSN::CALLpcrel32:
  case INSN::CALL64pcrel32:
    iinfo.type = INSN_X64_CALL;
    break;
  case INSN::CALL16m:
  case INSN::CALL32m:
  case INSN::CALL64m:
    iinfo.type = INSN_X64_CALLMEM;
    break;
  case INSN::CALL16r:
  case INSN::CALL32r:
  case INSN::CALL64r:
    iinfo.type = INSN_X64_CALLREG;
    break;
  case INSN::JMP_1:
  case INSN::JMP_2:
  case INSN::JMP_4:
    iinfo.type = INSN_X64_JUMP;
    break;
  case INSN::JMP16m:
  case INSN::JMP32m:
  case INSN::JMP64m:
    iinfo.type = INSN_X64_JUMPMEM;
    break;
  case INSN::JMP16r:
  case INSN::JMP32r:
  case INSN::JMP64r:
    iinfo.type = INSN_X64_JUMPREG;
    break;
  case INSN::MOV64rm:
    iinfo.type = INSN_X64_MOV64RM;
    break;
  case INSN::MOV32rm:
    iinfo.type = INSN_X64_MOV32RM;
    break;
  case INSN::MOV16rm:
    iinfo.type = INSN_X64_MOV16RM;
    break;
  case INSN::MOV8rm:
    iinfo.type = INSN_X64_MOV8RM;
    break;
  case INSN::MOV64mr:
    iinfo.type = INSN_X64_MOV64MR;
    break;
  case INSN::MOV32mr:
    iinfo.type = INSN_X64_MOV32MR;
    break;
  case INSN::MOV16mr:
    iinfo.type = INSN_X64_MOV16MR;
    break;
  case INSN::MOV8mr:
    iinfo.type = INSN_X64_MOV8MR;
    break;
  case INSN::MOV64mi32:
    iinfo.type = INSN_X64_MOV64MI32;
    break;
  case INSN::MOV32mi:
    iinfo.type = INSN_X64_MOV32MI;
    break;
  case INSN::MOV16mi:
    iinfo.type = INSN_X64_MOV16MI;
    break;
  case INSN::MOV8mi:
    iinfo.type = INSN_X64_MOV8MI;
    break;
  case INSN::LEA32r:
    iinfo.type = INSN_X64_LEA32;
    break;
  case INSN::LEA64r:
    iinfo.type = INSN_X64_LEA64;
    break;
  case INSN::MOVAPSrm:
    iinfo.type = INSN_X64_MOVAPSRM;
    break;
  case INSN::MOVAPSmr:
    iinfo.type = INSN_X64_MOVAPSMR;
    break;
  case INSN::MOVUPSrm:
    iinfo.type = INSN_X64_MOVUPSRM;
    break;
  case INSN::MOVUPSmr:
    iinfo.type = INSN_X64_MOVUPSMR;
    break;
  case INSN::MOVAPDrm:
    iinfo.type = INSN_X64_MOVAPDRM;
    break;
  case INSN::MOVAPDmr:
    iinfo.type = INSN_X64_MOVAPDMR;
    break;
  case INSN::MOVUPDrm:
    iinfo.type = INSN_X64_MOVUPDRM;
    break;
  case INSN::MOVUPDmr:
    iinfo.type = INSN_X64_MOVUPDMR;
    break;
  case INSN::CMP8mi:
    iinfo.type = INSN_X64_CMP8MI;
    break;
  case INSN::CMP8mi8:
    iinfo.type = INSN_X64_CMP8MI8;
    break;
  case INSN::CMP16mi:
    iinfo.type = INSN_X64_CMP16MI;
    break;
  case INSN::CMP16mi8:
    iinfo.type = INSN_X64_CMP16MI8;
    break;
  case INSN::CMP32mi:
    iinfo.type = INSN_X64_CMP32MI;
    break;
  case INSN::CMP32mi8:
    iinfo.type = INSN_X64_CMP32MI8;
    break;
  case INSN::CMP64mi32:
    iinfo.type = INSN_X64_CMP64MI32;
    break;
  case INSN::CMP64mi8:
    iinfo.type = INSN_X64_CMP64MI8;
    break;
  case INSN::CMP8rm:
    iinfo.type = INSN_X64_CMP8RM;
    break;
  case INSN::CMP16rm:
    iinfo.type = INSN_X64_CMP16RM;
    break;
  case INSN::CMP32rm:
    iinfo.type = INSN_X64_CMP32RM;
    break;
  case INSN::CMP64rm:
    iinfo.type = INSN_X64_CMP64RM;
    break;
  case INSN::MOVSX16rm8:
    iinfo.type = INSN_X64_MOVSX16RM8;
    break;
  case INSN::MOVSX16rm16:
    iinfo.type = INSN_X64_MOVSX16RM16;
    break;
  case INSN::MOVSX16rm32:
    iinfo.type = INSN_X64_MOVSX16RM32;
    break;
  case INSN::MOVSX32rm8:
    iinfo.type = INSN_X64_MOVSX32RM8;
    break;
  case INSN::MOVSX32rm16:
    iinfo.type = INSN_X64_MOVSX32RM16;
    break;
  case INSN::MOVSX32rm32:
    iinfo.type = INSN_X64_MOVSX32RM32;
    break;
  case INSN::MOVSX64rm8:
    iinfo.type = INSN_X64_MOVSX64RM8;
    break;
  case INSN::MOVSX64rm16:
    iinfo.type = INSN_X64_MOVSX64RM16;
    break;
  case INSN::MOVSX64rm32:
    iinfo.type = INSN_X64_MOVSX64RM32;
    break;
  case INSN::TEST8mi:
    iinfo.type = INSN_X64_TEST8MI;
    break;
  case INSN::TEST8mr:
    iinfo.type = INSN_X64_TEST8MR;
    break;
  case INSN::TEST16mi:
    iinfo.type = INSN_X64_TEST16MI;
    break;
  case INSN::TEST16mr:
    iinfo.type = INSN_X64_TEST16MR;
    break;
  case INSN::TEST32mi:
    iinfo.type = INSN_X64_TEST32MI;
    break;
  case INSN::TEST32mr:
    iinfo.type = INSN_X64_TEST32MR;
    break;
  case INSN::TEST64mi32:
    iinfo.type = INSN_X64_TEST64MI32;
    break;
  case INSN::TEST64mr:
    iinfo.type = INSN_X64_TEST64MR;
    break;
  default:
    iinfo.type = INSN_HARDWARE;
    break;
  }
}

using SymbolRef = object::SymbolRef;

static SymbolRef::Type convert_reloc_type(ArchType arch, ObjectType otype,
                                          uint64_t rtype) {
#define MACHO_MAGIC_BIT 0x10000
#define ELF_MAGIC_BIT 0x20000
#define COFF_MAGIC_BIT 0x40000

  switch (otype) {
  case MachO_Reloc:
    rtype |= MACHO_MAGIC_BIT;
    break;
  case ELF_Reloc:
    rtype |= ELF_MAGIC_BIT;
    break;
  default:
    rtype |= COFF_MAGIC_BIT;
    break;
  }

  switch (arch) {
  case AArch64: {
    switch (rtype) {
    case MachO::ARM64_RELOC_GOT_LOAD_PAGE21 | MACHO_MAGIC_BIT:
    case ELF::R_AARCH64_GOTREL64 | ELF_MAGIC_BIT:
    case ELF::R_AARCH64_GOT_LD_PREL19 | ELF_MAGIC_BIT:
    case ELF::R_AARCH64_ADR_GOT_PAGE | ELF_MAGIC_BIT:
    case COFF::RelocationTypesARM64::IMAGE_REL_ARM64_PAGEBASE_REL21 |
        COFF_MAGIC_BIT:
      return SymbolRef::ST_Data;
    default:
      break;
    }
    break;
  }
  case X86_64: {
    switch (rtype) {
    case MachO::X86_64_RELOC_GOT | MACHO_MAGIC_BIT:
    case MachO::X86_64_RELOC_GOT_LOAD | MACHO_MAGIC_BIT:
    case ELF::R_X86_64_GOTPCREL | ELF_MAGIC_BIT:
    case COFF::RelocationTypeAMD64::IMAGE_REL_AMD64_ADDR64 | COFF_MAGIC_BIT:
      return SymbolRef::ST_Data;
    default:
      break;
    }
    break;
  }
  default:
    break;
  }
  return SymbolRef::ST_Function;
}

void Object::decodeInsns(TextSection &text) {
  // load text relocations
  std::map<uint64_t, object::RelocationRef> relocs;
  for (auto &s : ofile_->sections()) {
    if (s.getIndex() != text.index) {
      continue;
    }
    for (auto r : s.relocations()) {
      auto sym = r.getSymbol();
      auto expType = sym->getType();
      if (!expType)
        continue;
      // only load data/function symbols
      switch (expType.get()) {
      case SymbolRef::ST_Unknown:
      case SymbolRef::ST_Data:
      case SymbolRef::ST_Function:
        relocs.insert({s.getAddress() + r.getOffset(), r});
        break;
      default:
        break;
      }
    }
    break;
  }

  int skipsz = arch_ == AArch64 ? 4 : 1;
  // decode instructions in text section
  MCInst inst;
  for (auto opc = text.vm, opcend = text.vm + text.size; opc < opcend;) {
    uint64_t size = 0;
    auto status = odiser_.DT->DisAsm->getInstruction(
        inst, size, BuildIDRef(reinterpret_cast<const uint8_t *>(opc), 16), opc,
        outs());
    InsnInfo iinfo{};
    iinfo.rva = text.rva + opc - text.vm;
    switch (status) {
    case MCDisassembler::Fail: {
      iinfo.type = INSN_ABORT;
      iinfo.len = skipsz;
      break;
    }
    case MCDisassembler::SoftFail: {
      iinfo.type = INSN_ABORT;
      iinfo.len = size ? static_cast<uint32_t>(size) : skipsz;
      break;
    }
    default: {
      iinfo.len = static_cast<uint32_t>(size);
      // check and resolve the relocation symbol
      auto found = relocs.find(vm2rva(opc));
      if (found != relocs.end()) {
        auto cureloc = found->second;
        auto sym = cureloc.getSymbol();
        auto expName = sym->getName();
        auto expFlags = sym->getFlags();
        if (!expName || !expFlags) {
          // never be here
          log_print(Runtime,
                    "Fatal error, the symbol name/type/flags of '{:x}' is "
                    "missing for "
                    "relocation.",
                    vm2rva(opc));
          abort();
        }
        auto name = expName.get();
        // check the existed relocation
        auto rit = irelocs_.end();
        for (auto it = irelocs_.begin(), end = irelocs_.end(); it != end;
             it++) {
          if (name == it->name) {
            rit = it;
            break;
          }
        }
        auto symtype = convert_reloc_type(arch(), type(), cureloc.getType());
        if (rit == irelocs_.end()) {
          if (expFlags.get() & SymbolRef::SF_Undefined) {
            // locate and insert a new extern relocation
            auto rtaddr =
                Loader::locateSymbol(name, symtype == SymbolRef::ST_Data);
            rit = irelocs_.insert(irelocs_.end(),
                                  RelocInfo{name.data(), rtaddr, symtype});
          } else {
            // insert a new local relocation
            auto expSect = sym->getSection();
            auto expAddr = sym->getAddress();
            if (!expSect || !expAddr) {
              // never be here
              log_print(
                  Runtime,
                  "Fatal error, the symbol section/address of '{}'.'{:x}' is "
                  "missing for "
                  "relocation.",
                  name.data(), vm2rva(opc));
              abort();
            }
            bool dyn = false;
            auto sectname = expSect.get()->getName();
            if (!sectname) {
              // never be here
              log_print(
                  Runtime,
                  "Fatal error, the section name is missing for relocation.");
              abort();
            }
            auto symoff = expAddr.get() - expSect.get()->getAddress();
            for (auto &ds : dynsects_) {
              if (sectname.get() == ds.name) {
                // dynamically allocated section
                dyn = true;

                auto rtaddr =
                    reinterpret_cast<const void *>(ds.buffer.data() + symoff);
                rit = irelocs_.insert(irelocs_.end(),
                                      RelocInfo{name.data(), rtaddr, symtype});
                break;
              }
            }
            if (!dyn) {
              // inner section from file
              auto expContent = expSect.get()->getContents();
              if (!expContent) {
                // never be here
                log_print(
                    Runtime,
                    "Fatal error, the section content of '{}' is missing for "
                    "relocation.",
                    sectname->data());
                abort();
              }
              auto rtaddr =
                  reinterpret_cast<const void *>(expContent->data() + symoff);
              rit = irelocs_.insert(irelocs_.end(),
                                    RelocInfo{name.data(), rtaddr, symtype});
            }
          }
          if (0) {
            log_print(Develop, "Relocated {} symbol {} at {}.",
                      symtype == SymbolRef::ST_Data ? "data" : "func",
                      rit->name, rit->target);
          }
        }
        // record its relocation index
        iinfo.rflag = 1;
        iinfo.reloc = rit - irelocs_.begin();
      }
      // convert llvm opcode to icpp InsnType
      std::function<uint16_t(unsigned)> llvm2uc_register;
      if (arch() == AArch64) {
        llvm2uc_register = llvm2ucRegisterAArch64;
        parseInstAArch64(inst, opc, idecinfs_, iinfo);
      } else {
        llvm2uc_register = llvm2ucRegisterX64;
        parseInstX64(inst, opc, idecinfs_, iinfo);
      }
      // encode none-hardware instruction if there's no one
      if (iinfo.type != INSN_HARDWARE &&
          idecinfs_.find(std::string(reinterpret_cast<char *>(opc),
                                     iinfo.len)) == idecinfs_.end()) {
        auto newi =
            idecinfs_
                .insert({std::string(reinterpret_cast<char *>(opc), iinfo.len),
                         std::string()})
                .first;
        auto optr = const_cast<std::string *>(&newi->second);
        // we encode the instruction operands as follows:
        // if it's a register, then encode it to uc register index as uint16_t
        // if it's an immediate, then encode it as uint64_t
        for (unsigned i = 0; i < inst.getNumOperands(); i++) {
          auto opr = inst.getOperand(i);
          if (opr.isImm()) {
            auto imm = opr.getImm();
            optr->append(
                std::string(reinterpret_cast<char *>(&imm), sizeof(imm)));
          } else if (opr.isReg()) {
            auto reg = llvm2uc_register(opr.getReg());
            optr->append(
                std::string(reinterpret_cast<char *>(&reg), sizeof(reg)));
          } else {
            // nerver be here
            log_print(Runtime, "Fatal error when decoding instruction at {:x}.",
                      vm2rva(opc));
            abort();
          }
        }
      }
      break;
    }
    } // end of switch
    text.iinfs.push_back(iinfo);
    opc += iinfo.len;
  }
}

} // namespace icpp
