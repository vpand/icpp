/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

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

static void AlignToInstStartColumn(size_t Start, const MCSubtargetInfo &STI,
                                   raw_ostream &OS) {
  // The output of printInst starts with a tab. Print some spaces so that
  // the tab has 1 column and advances to the target tab stop.
  unsigned TabStop = getInstStartColumn(STI);
  unsigned Column = OS.tell() - Start;
  OS.indent(Column < TabStop - 1 ? TabStop - 1 - Column : 7 - Column % 8);
}

void objdump::printRawData(ArrayRef<uint8_t> Bytes, uint64_t Address,
                           formatted_raw_ostream &OS,
                           MCSubtargetInfo const &STI) {
  size_t Start = OS.tell();
  if (LeadingAddr)
    OS << format("%8" PRIx64 ":", Address);
  if (ShowRawInsn) {
    OS << ' ';
    dumpBytes(Bytes, OS);
  }
  AlignToInstStartColumn(Start, STI, OS);
}

namespace icpp {

// This class represents the BBAddrMap and PGOMap associated with a single
// function.
class BBAddrMapFunctionEntry {
public:
  BBAddrMapFunctionEntry(BBAddrMap AddrMap, PGOAnalysisMap PGOMap)
      : AddrMap(std::move(AddrMap)), PGOMap(std::move(PGOMap)) {}

  const BBAddrMap &getAddrMap() const { return AddrMap; }

  // Returns the PGO string associated with the entry of index `PGOBBEntryIndex`
  // in `PGOMap`. If PrettyPGOAnalysis is true, prints BFI as relative frequency
  // and BPI as percentage. Otherwise raw values are displayed.
  std::string constructPGOLabelString(size_t PGOBBEntryIndex,
                                      bool PrettyPGOAnalysis) const {
    if (!PGOMap.FeatEnable.hasPGOAnalysis())
      return "";
    std::string PGOString;
    raw_string_ostream PGOSS(PGOString);

    PGOSS << " (";
    if (PGOMap.FeatEnable.FuncEntryCount && PGOBBEntryIndex == 0) {
      PGOSS << "Entry count: " << Twine(PGOMap.FuncEntryCount);
      if (PGOMap.FeatEnable.hasPGOAnalysisBBData()) {
        PGOSS << ", ";
      }
    }

    if (PGOMap.FeatEnable.hasPGOAnalysisBBData()) {

      assert(PGOBBEntryIndex < PGOMap.BBEntries.size() &&
             "Expected PGOAnalysisMap and BBAddrMap to have the same entries");
      const PGOAnalysisMap::PGOBBEntry &PGOBBEntry =
          PGOMap.BBEntries[PGOBBEntryIndex];

      if (PGOMap.FeatEnable.BBFreq) {
        PGOSS << "Frequency: ";
        if (PrettyPGOAnalysis)
          printRelativeBlockFreq(PGOSS, PGOMap.BBEntries.front().BlockFreq,
                                 PGOBBEntry.BlockFreq);
        else
          PGOSS << Twine(PGOBBEntry.BlockFreq.getFrequency());
        if (PGOMap.FeatEnable.BrProb && PGOBBEntry.Successors.size() > 0) {
          PGOSS << ", ";
        }
      }
      if (PGOMap.FeatEnable.BrProb && PGOBBEntry.Successors.size() > 0) {
        PGOSS << "Successors: ";
        interleaveComma(
            PGOBBEntry.Successors, PGOSS,
            [&](const PGOAnalysisMap::PGOBBEntry::SuccessorEntry &SE) {
              PGOSS << "BB" << SE.ID << ":";
              if (PrettyPGOAnalysis)
                PGOSS << "[" << SE.Prob << "]";
              else
                PGOSS.write_hex(SE.Prob.getNumerator());
            });
      }
    }
    PGOSS << ")";

    return PGOString;
  }

private:
  const BBAddrMap AddrMap;
  const PGOAnalysisMap PGOMap;
};

// This class represents the BBAddrMap and PGOMap of potentially multiple
// functions in a section.
class BBAddrMapInfo {
public:
  void clear() {
    FunctionAddrToMap.clear();
    RangeBaseAddrToFunctionAddr.clear();
  }

  bool empty() const { return FunctionAddrToMap.empty(); }

  void AddFunctionEntry(BBAddrMap AddrMap, PGOAnalysisMap PGOMap) {
    uint64_t FunctionAddr = AddrMap.getFunctionAddress();
    for (size_t I = 1; I < AddrMap.BBRanges.size(); ++I)
      RangeBaseAddrToFunctionAddr.emplace(AddrMap.BBRanges[I].BaseAddress,
                                          FunctionAddr);
    [[maybe_unused]] auto R = FunctionAddrToMap.try_emplace(
        FunctionAddr, std::move(AddrMap), std::move(PGOMap));
    assert(R.second && "duplicate function address");
  }

  // Returns the BBAddrMap entry for the function associated with `BaseAddress`.
  // `BaseAddress` could be the function address or the address of a range
  // associated with that function. Returns `nullptr` if `BaseAddress` is not
  // mapped to any entry.
  const BBAddrMapFunctionEntry *getEntryForAddress(uint64_t BaseAddress) const {
    uint64_t FunctionAddr = BaseAddress;
    auto S = RangeBaseAddrToFunctionAddr.find(BaseAddress);
    if (S != RangeBaseAddrToFunctionAddr.end())
      FunctionAddr = S->second;
    auto R = FunctionAddrToMap.find(FunctionAddr);
    if (R == FunctionAddrToMap.end())
      return nullptr;
    return &R->second;
  }

private:
  std::unordered_map<uint64_t, BBAddrMapFunctionEntry> FunctionAddrToMap;
  std::unordered_map<uint64_t, uint64_t> RangeBaseAddrToFunctionAddr;
};

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

namespace {

static bool isAArch64Elf(const ObjectFile &Obj) {
  const auto *Elf = dyn_cast<ELFObjectFileBase>(&Obj);
  return Elf && Elf->getEMachine() == ELF::EM_AARCH64;
}

static bool isArmElf(const ObjectFile &Obj) {
  const auto *Elf = dyn_cast<ELFObjectFileBase>(&Obj);
  return Elf && Elf->getEMachine() == ELF::EM_ARM;
}

static bool isCSKYElf(const ObjectFile &Obj) {
  const auto *Elf = dyn_cast<ELFObjectFileBase>(&Obj);
  return Elf && Elf->getEMachine() == ELF::EM_CSKY;
}

static bool hasMappingSymbols(const ObjectFile &Obj) {
  return isArmElf(Obj) || isAArch64Elf(Obj) || isCSKYElf(Obj);
}

class PrettyPrinter {
public:
  virtual ~PrettyPrinter() = default;
  virtual void
  printInst(MCInstPrinter &IP, const MCInst *MI, ArrayRef<uint8_t> Bytes,
            object::SectionedAddress Address, formatted_raw_ostream &OS,
            StringRef Annot, MCSubtargetInfo const &STI, SourcePrinter *SP,
            StringRef ObjectFilename, std::vector<RelocationRef> *Rels,
            LiveVariablePrinter &LVP) {
    if (SP && (PrintSource || PrintLines))
      SP->printSourceLine(OS, Address, ObjectFilename, LVP);
    LVP.printBetweenInsts(OS, false);

    printRawData(Bytes, Address.Address, OS, STI);

    if (MI) {
      // See MCInstPrinter::printInst. On targets where a PC relative immediate
      // is relative to the next instruction and the length of a MCInst is
      // difficult to measure (x86), this is the address of the next
      // instruction.
      uint64_t Addr =
          Address.Address + (STI.getTargetTriple().isX86() ? Bytes.size() : 0);
      IP.printInst(MI, Addr, "", STI, OS);
    } else
      OS << "\t<unknown>";
  }
};
PrettyPrinter PrettyPrinterInst;

class ARMPrettyPrinter : public PrettyPrinter {
public:
  void printInst(MCInstPrinter &IP, const MCInst *MI, ArrayRef<uint8_t> Bytes,
                 object::SectionedAddress Address, formatted_raw_ostream &OS,
                 StringRef Annot, MCSubtargetInfo const &STI, SourcePrinter *SP,
                 StringRef ObjectFilename, std::vector<RelocationRef> *Rels,
                 LiveVariablePrinter &LVP) override {
    if (SP && (PrintSource || PrintLines))
      SP->printSourceLine(OS, Address, ObjectFilename, LVP);
    LVP.printBetweenInsts(OS, false);

    size_t Start = OS.tell();
    if (LeadingAddr)
      OS << format("%8" PRIx64 ":", Address.Address);
    if (ShowRawInsn) {
      size_t Pos = 0, End = Bytes.size();
      if (STI.checkFeatures("+thumb-mode")) {
        for (; Pos + 2 <= End; Pos += 2)
          OS << ' '
             << format_hex_no_prefix(
                    llvm::support::endian::read<uint16_t>(
                        Bytes.data() + Pos, InstructionEndianness),
                    4);
      } else {
        for (; Pos + 4 <= End; Pos += 4)
          OS << ' '
             << format_hex_no_prefix(
                    llvm::support::endian::read<uint32_t>(
                        Bytes.data() + Pos, InstructionEndianness),
                    8);
      }
      if (Pos < End) {
        OS << ' ';
        dumpBytes(Bytes.slice(Pos), OS);
      }
    }

    AlignToInstStartColumn(Start, STI, OS);

    if (MI) {
      IP.printInst(MI, Address.Address, "", STI, OS);
    } else
      OS << "\t<unknown>";
  }

  void setInstructionEndianness(llvm::endianness Endianness) {
    InstructionEndianness = Endianness;
  }

private:
  llvm::endianness InstructionEndianness = llvm::endianness::little;
};
ARMPrettyPrinter ARMPrettyPrinterInst;

class AArch64PrettyPrinter : public PrettyPrinter {
public:
  void printInst(MCInstPrinter &IP, const MCInst *MI, ArrayRef<uint8_t> Bytes,
                 object::SectionedAddress Address, formatted_raw_ostream &OS,
                 StringRef Annot, MCSubtargetInfo const &STI, SourcePrinter *SP,
                 StringRef ObjectFilename, std::vector<RelocationRef> *Rels,
                 LiveVariablePrinter &LVP) override {
    if (SP && (PrintSource || PrintLines))
      SP->printSourceLine(OS, Address, ObjectFilename, LVP);
    LVP.printBetweenInsts(OS, false);

    size_t Start = OS.tell();
    if (LeadingAddr)
      OS << format("%8" PRIx64 ":", Address.Address);
    if (ShowRawInsn) {
      size_t Pos = 0, End = Bytes.size();
      for (; Pos + 4 <= End; Pos += 4)
        OS << ' '
           << format_hex_no_prefix(
                  llvm::support::endian::read<uint32_t>(
                      Bytes.data() + Pos, llvm::endianness::little),
                  8);
      if (Pos < End) {
        OS << ' ';
        dumpBytes(Bytes.slice(Pos), OS);
      }
    }

    AlignToInstStartColumn(Start, STI, OS);

    if (MI) {
      IP.printInst(MI, Address.Address, "", STI, OS);
    } else
      OS << "\t<unknown>";
  }
};
AArch64PrettyPrinter AArch64PrettyPrinterInst;

PrettyPrinter &selectPrettyPrinter(Triple const &Triple) {
  switch (Triple.getArch()) {
  default:
    return PrettyPrinterInst;
  case Triple::arm:
  case Triple::armeb:
  case Triple::thumb:
  case Triple::thumbeb:
    return ARMPrettyPrinterInst;
  case Triple::aarch64:
  case Triple::aarch64_be:
  case Triple::aarch64_32:
    return AArch64PrettyPrinterInst;
  }
}

class DisassemblerTarget {
public:
  const Target *TheTarget;
  std::unique_ptr<const MCSubtargetInfo> SubtargetInfo;
  std::shared_ptr<MCContext> Context;
  std::unique_ptr<MCDisassembler> DisAsm;
  std::shared_ptr<MCInstrAnalysis> InstrAnalysis;
  std::shared_ptr<MCInstPrinter> InstPrinter;
  PrettyPrinter *Printer;

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
    : TheTarget(TheTarget), Printer(&selectPrettyPrinter(Triple(TripleName))),
      RegisterInfo(TheTarget->createMCRegInfo(TripleName)) {
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
      Printer(Other.Printer), RegisterInfo(Other.RegisterInfo),
      AsmInfo(Other.AsmInfo), InstrInfo(Other.InstrInfo),
      ObjectFileInfo(Other.ObjectFileInfo) {}
} // namespace

static uint8_t getElfSymbolType(const ObjectFile &Obj, const SymbolRef &Sym) {
  assert(Obj.isELF());
  if (auto *Elf32LEObj = dyn_cast<ELF32LEObjectFile>(&Obj))
    return unwrapOrError(Elf32LEObj->getSymbol(Sym.getRawDataRefImpl()),
                         Obj.getFileName())
        ->getType();
  if (auto *Elf64LEObj = dyn_cast<ELF64LEObjectFile>(&Obj))
    return unwrapOrError(Elf64LEObj->getSymbol(Sym.getRawDataRefImpl()),
                         Obj.getFileName())
        ->getType();
  if (auto *Elf32BEObj = dyn_cast<ELF32BEObjectFile>(&Obj))
    return unwrapOrError(Elf32BEObj->getSymbol(Sym.getRawDataRefImpl()),
                         Obj.getFileName())
        ->getType();
  if (auto *Elf64BEObj = cast<ELF64BEObjectFile>(&Obj))
    return unwrapOrError(Elf64BEObj->getSymbol(Sym.getRawDataRefImpl()),
                         Obj.getFileName())
        ->getType();
  llvm_unreachable("Unsupported binary format");
}

template <class ELFT>
static void
addDynamicElfSymbols(const ELFObjectFile<ELFT> &Obj,
                     std::map<SectionRef, SectionSymbolsTy> &AllSymbols) {
  for (auto Symbol : Obj.getDynamicSymbolIterators()) {
    uint8_t SymbolType = Symbol.getELFType();
    if (SymbolType == ELF::STT_SECTION)
      continue;

    uint64_t Address = unwrapOrError(Symbol.getAddress(), Obj.getFileName());
    // ELFSymbolRef::getAddress() returns size instead of value for common
    // symbols which is not desirable for disassembly output. Overriding.
    if (SymbolType == ELF::STT_COMMON)
      Address = unwrapOrError(Obj.getSymbol(Symbol.getRawDataRefImpl()),
                              Obj.getFileName())
                    ->st_value;

    StringRef Name = unwrapOrError(Symbol.getName(), Obj.getFileName());
    if (Name.empty())
      continue;

    section_iterator SecI =
        unwrapOrError(Symbol.getSection(), Obj.getFileName());
    if (SecI == Obj.section_end())
      continue;

    AllSymbols[*SecI].emplace_back(Address, Name, SymbolType);
  }
}

static void
addDynamicElfSymbols(const ELFObjectFileBase &Obj,
                     std::map<SectionRef, SectionSymbolsTy> &AllSymbols) {
  if (auto *Elf32LEObj = dyn_cast<ELF32LEObjectFile>(&Obj))
    addDynamicElfSymbols(*Elf32LEObj, AllSymbols);
  else if (auto *Elf64LEObj = dyn_cast<ELF64LEObjectFile>(&Obj))
    addDynamicElfSymbols(*Elf64LEObj, AllSymbols);
  else if (auto *Elf32BEObj = dyn_cast<ELF32BEObjectFile>(&Obj))
    addDynamicElfSymbols(*Elf32BEObj, AllSymbols);
  else if (auto *Elf64BEObj = cast<ELF64BEObjectFile>(&Obj))
    addDynamicElfSymbols(*Elf64BEObj, AllSymbols);
  else
    llvm_unreachable("Unsupported binary format");
}

static void addPltEntries(const ObjectFile &Obj,
                          std::map<SectionRef, SectionSymbolsTy> &AllSymbols,
                          StringSaver &Saver) {
  auto *ElfObj = dyn_cast<ELFObjectFileBase>(&Obj);
  if (!ElfObj)
    return;
  DenseMap<StringRef, SectionRef> Sections;
  for (SectionRef Section : Obj.sections()) {
    Expected<StringRef> SecNameOrErr = Section.getName();
    if (!SecNameOrErr) {
      consumeError(SecNameOrErr.takeError());
      continue;
    }
    Sections[*SecNameOrErr] = Section;
  }
  for (auto Plt : ElfObj->getPltEntries()) {
    if (Plt.Symbol) {
      SymbolRef Symbol(*Plt.Symbol, ElfObj);
      uint8_t SymbolType = getElfSymbolType(Obj, Symbol);
      if (Expected<StringRef> NameOrErr = Symbol.getName()) {
        if (!NameOrErr->empty())
          AllSymbols[Sections[Plt.Section]].emplace_back(
              Plt.Address, Saver.save((*NameOrErr + "@plt").str()), SymbolType);
        continue;
      } else {
        // The warning has been reported in disassembleObject().
        consumeError(NameOrErr.takeError());
      }
    }
    reportWarning("PLT entry at 0x" + Twine::utohexstr(Plt.Address) +
                      " references an invalid symbol",
                  Obj.getFileName());
  }
}

// Normally the disassembly output will skip blocks of zeroes. This function
// returns the number of zero bytes that can be skipped when dumping the
// disassembly of the instructions in Buf.
static size_t countSkippableZeroBytes(ArrayRef<uint8_t> Buf) {
  // Find the number of leading zeroes.
  size_t N = 0;
  while (N < Buf.size() && !Buf[N])
    ++N;

  // We may want to skip blocks of zero bytes, but unless we see
  // at least 8 of them in a row.
  if (N < 8)
    return 0;

  // We skip zeroes in multiples of 4 because do not want to truncate an
  // instruction if it starts with a zero byte.
  return N & ~0x3;
}

namespace {
struct FilterResult {
  // True if the section should not be skipped.
  bool Keep;

  // True if the index counter should be incremented, even if the section should
  // be skipped. For example, sections may be skipped if they are not included
  // in the --section flag, but we still want those to count toward the section
  // count.
  bool IncrementIndex;
};
} // namespace

static FilterResult checkSectionFilter(object::SectionRef S) {
  if (FilterSections.empty())
    return {/*Keep=*/true, /*IncrementIndex=*/true};

  Expected<StringRef> SecNameOrErr = S.getName();
  if (!SecNameOrErr) {
    consumeError(SecNameOrErr.takeError());
    return {/*Keep=*/false, /*IncrementIndex=*/false};
  }
  StringRef SecName = *SecNameOrErr;

  // StringSet does not allow empty key so avoid adding sections with
  // no name (such as the section with index 0) here.
  if (!SecName.empty())
    FoundSectionSet.insert(SecName);

  // Only show the section if it's in the FilterSections list, but always
  // increment so the indexing is stable.
  return {/*Keep=*/is_contained(FilterSections, SecName),
          /*IncrementIndex=*/true};
}

// Returns a map from sections to their relocations.
static std::map<SectionRef, std::vector<RelocationRef>>
getRelocsMap(object::ObjectFile const &Obj) {
  std::map<SectionRef, std::vector<RelocationRef>> Ret;
  uint64_t I = (uint64_t)-1;
  for (SectionRef Sec : Obj.sections()) {
    ++I;
    Expected<section_iterator> RelocatedOrErr = Sec.getRelocatedSection();
    if (!RelocatedOrErr)
      reportError(Obj.getFileName(),
                  "section (" + Twine(I) +
                      "): failed to get a relocated section: " +
                      toString(RelocatedOrErr.takeError()));

    section_iterator Relocated = *RelocatedOrErr;
    if (Relocated == Obj.section_end() || !checkSectionFilter(*Relocated).Keep)
      continue;
    std::vector<RelocationRef> &V = Ret[*Relocated];
    append_range(V, Sec.relocations());
    // Sort relocations by address.
    llvm::stable_sort(V, isRelocAddressLess);
  }
  return Ret;
}

// Used for --adjust-vma to check if address should be adjusted by the
// specified value for a given section.
// For ELF we do not adjust non-allocatable sections like debug ones,
// because they are not loadable.
// TODO: implement for other file formats.
static bool shouldAdjustVA(const SectionRef &Section) {
  const ObjectFile *Obj = Section.getObject();
  if (Obj->isELF())
    return ELFSectionRef(Section).getFlags() & ELF::SHF_ALLOC;
  return false;
}

typedef std::pair<uint64_t, char> MappingSymbolPair;
static char getMappingSymbolKind(ArrayRef<MappingSymbolPair> MappingSymbols,
                                 uint64_t Address) {
  auto It =
      partition_point(MappingSymbols, [Address](const MappingSymbolPair &Val) {
        return Val.first <= Address;
      });
  // Return zero for any address before the first mapping symbol; this means
  // we should use the default disassembly mode, depending on the target.
  if (It == MappingSymbols.begin())
    return '\x00';
  return (It - 1)->second;
}

struct BBAddrMapLabel {
  std::string BlockLabel;
  std::string PGOAnalysis;
};

static void collectBBAddrMapLabels(
    const BBAddrMapInfo &FullAddrMap, uint64_t SectionAddr, uint64_t Start,
    uint64_t End,
    std::unordered_map<uint64_t, std::vector<BBAddrMapLabel>> &Labels) {
  if (FullAddrMap.empty())
    return;
  Labels.clear();
  uint64_t StartAddress = SectionAddr + Start;
  uint64_t EndAddress = SectionAddr + End;
  const BBAddrMapFunctionEntry *FunctionMap =
      FullAddrMap.getEntryForAddress(StartAddress);
  if (!FunctionMap)
    return;
  std::optional<size_t> BBRangeIndex =
      FunctionMap->getAddrMap().getBBRangeIndexForBaseAddress(StartAddress);
  if (!BBRangeIndex)
    return;
  size_t NumBBEntriesBeforeRange = 0;
  for (size_t I = 0; I < *BBRangeIndex; ++I)
    NumBBEntriesBeforeRange +=
        FunctionMap->getAddrMap().BBRanges[I].BBEntries.size();
  const auto &BBRange = FunctionMap->getAddrMap().BBRanges[*BBRangeIndex];
  for (size_t I = 0; I < BBRange.BBEntries.size(); ++I) {
    const BBAddrMap::BBEntry &BBEntry = BBRange.BBEntries[I];
    uint64_t BBAddress = BBEntry.Offset + BBRange.BaseAddress;
    if (BBAddress >= EndAddress)
      continue;

    std::string LabelString = ("BB" + Twine(BBEntry.ID)).str();
    Labels[BBAddress].push_back(
        {LabelString, FunctionMap->constructPGOLabelString(
                          NumBBEntriesBeforeRange + I, false)});
  }
}

static void
collectLocalBranchTargets(ArrayRef<uint8_t> Bytes, MCInstrAnalysis *MIA,
                          MCDisassembler *DisAsm, MCInstPrinter *IP,
                          const MCSubtargetInfo *STI, uint64_t SectionAddr,
                          uint64_t Start, uint64_t End,
                          std::unordered_map<uint64_t, std::string> &Labels) {
  // So far only supports PowerPC and X86.
  const bool isPPC = STI->getTargetTriple().isPPC();
  if (!isPPC && !STI->getTargetTriple().isX86())
    return;

  if (MIA)
    MIA->resetState();

  Labels.clear();
  unsigned LabelCount = 0;
  Start += SectionAddr;
  End += SectionAddr;
  const bool isXCOFF = STI->getTargetTriple().isOSBinFormatXCOFF();
  for (uint64_t Index = Start; Index < End;) {
    // Disassemble a real instruction and record function-local branch labels.
    MCInst Inst;
    uint64_t Size;
    ArrayRef<uint8_t> ThisBytes = Bytes.slice(Index - SectionAddr);
    bool Disassembled =
        DisAsm->getInstruction(Inst, Size, ThisBytes, Index, nulls());
    if (Size == 0)
      Size = std::min<uint64_t>(ThisBytes.size(),
                                DisAsm->suggestBytesToSkip(ThisBytes, Index));

    if (MIA) {
      if (Disassembled) {
        uint64_t Target;
        bool TargetKnown = MIA->evaluateBranch(Inst, Index, Size, Target);
        if (TargetKnown && (Target >= Start && Target < End) &&
            !Labels.count(Target)) {
          // On PowerPC and AIX, a function call is encoded as a branch to 0.
          // On other PowerPC platforms (ELF), a function call is encoded as
          // a branch to self. Do not add a label for these cases.
          if (!(isPPC &&
                ((Target == 0 && isXCOFF) || (Target == Index && !isXCOFF))))
            Labels[Target] = ("L" + Twine(LabelCount++)).str();
        }
        MIA->updateState(Inst, Index);
      } else
        MIA->resetState();
    }
    Index += Size;
  }
}

// Create an MCSymbolizer for the target and add it to the MCDisassembler.
// This is currently only used on AMDGPU, and assumes the format of the
// void * argument passed to AMDGPU's createMCSymbolizer.
static void addSymbolizer(
    MCContext &Ctx, const Target *Target, StringRef TripleName,
    MCDisassembler *DisAsm, uint64_t SectionAddr, ArrayRef<uint8_t> Bytes,
    SectionSymbolsTy &Symbols,
    std::vector<std::unique_ptr<std::string>> &SynthesizedLabelNames) {

  std::unique_ptr<MCRelocationInfo> RelInfo(
      Target->createMCRelocationInfo(TripleName, Ctx));
  if (!RelInfo)
    return;
  std::unique_ptr<MCSymbolizer> Symbolizer(Target->createMCSymbolizer(
      TripleName, nullptr, nullptr, &Symbols, &Ctx, std::move(RelInfo)));
  MCSymbolizer *SymbolizerPtr = &*Symbolizer;
  DisAsm->setSymbolizer(std::move(Symbolizer));
}

static StringRef getSegmentName(const MachOObjectFile *MachO,
                                const SectionRef &Section) {
  if (MachO) {
    DataRefImpl DR = Section.getRawDataRefImpl();
    StringRef SegmentName = MachO->getSectionFinalSegmentName(DR);
    return SegmentName;
  }
  return "";
}

static void emitPostInstructionInfo(formatted_raw_ostream &FOS,
                                    const MCAsmInfo &MAI,
                                    const MCSubtargetInfo &STI,
                                    StringRef Comments,
                                    LiveVariablePrinter &LVP) {
  do {
    if (!Comments.empty()) {
      // Emit a line of comments.
      StringRef Comment;
      std::tie(Comment, Comments) = Comments.split('\n');
      // MAI.getCommentColumn() assumes that instructions are printed at the
      // position of 8, while getInstStartColumn() returns the actual position.
      unsigned CommentColumn =
          MAI.getCommentColumn() - 8 + getInstStartColumn(STI);
      FOS.PadToColumn(CommentColumn);
      FOS << MAI.getCommentString() << ' ' << Comment;
    }
    LVP.printAfterInst(FOS);
    FOS << '\n';
  } while (!Comments.empty());
  FOS.flush();
}

static void createFakeELFSections(ObjectFile &Obj) {
  assert(Obj.isELF());
  if (auto *Elf32LEObj = dyn_cast<ELF32LEObjectFile>(&Obj))
    Elf32LEObj->createFakeSections();
  else if (auto *Elf64LEObj = dyn_cast<ELF64LEObjectFile>(&Obj))
    Elf64LEObj->createFakeSections();
  else if (auto *Elf32BEObj = dyn_cast<ELF32BEObjectFile>(&Obj))
    Elf32BEObj->createFakeSections();
  else if (auto *Elf64BEObj = cast<ELF64BEObjectFile>(&Obj))
    Elf64BEObj->createFakeSections();
  else
    llvm_unreachable("Unsupported binary format");
}

std::unique_ptr<BuildIDFetcher> BIDFetcher;

// Tries to fetch a more complete version of the given object file using its
// Build ID. Returns std::nullopt if nothing was found.
static std::optional<OwningBinary<Binary>>
fetchBinaryByBuildID(const ObjectFile &Obj) {
  object::BuildIDRef BuildID = getBuildID(&Obj);
  if (BuildID.empty())
    return std::nullopt;
  std::optional<std::string> Path = BIDFetcher->fetch(BuildID);
  if (!Path)
    return std::nullopt;
  Expected<OwningBinary<Binary>> DebugBinary = createBinary(*Path);
  if (!DebugBinary) {
    reportWarning(toString(DebugBinary.takeError()), *Path);
    return std::nullopt;
  }
  return std::move(*DebugBinary);
}

static SymbolInfoTy createDummySymbolInfo(const ObjectFile &Obj,
                                          const uint64_t Addr, StringRef &Name,
                                          uint8_t Type) {
  if (Obj.isXCOFF() && (SymbolDescription || TracebackTable))
    return SymbolInfoTy(std::nullopt, Addr, Name, std::nullopt, false);
  if (Obj.isWasm())
    return SymbolInfoTy(Addr, Name, wasm::WASM_SYMBOL_TYPE_SECTION);
  return SymbolInfoTy(Addr, Name, Type);
}

std::string Object::sourceInfo(uint64_t vm) {
  auto Obj = ofile_.get();
  std::string TripleName(triple()), Output;
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

  DisassemblerTarget PrimaryTarget(TheTarget, *Obj, TripleName, MCPU, Features);

  SourcePrinter SP(Obj, TheTarget->getName());
  raw_string_ostream OS(Output);
  formatted_raw_ostream FOS(OS);
  auto SectAddr = object::SectionedAddress{vm2rva(vm), textsecti_};
  LiveVariablePrinter LVP(*PrimaryTarget.Context->getRegisterInfo(),
                          *PrimaryTarget.SubtargetInfo);
  SP.printSourceLine(FOS, SectAddr, Obj->getFileName(), LVP);
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
  case INSN::MOV32ri:
  case INSN::MOV64ri:
    iinfo.type = INSN_X64_MOVI;
    break;
  case INSN::MOV32ao16:
  case INSN::MOV32ao32:
  case INSN::MOV32ao64:
  case INSN::MOV64ao32:
  case INSN::MOV64ao64:
    iinfo.type = INSN_X64_MOVIMEM;
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

void Object::decodeInsns() {
  auto Obj = ofile_.get();
  std::string TripleName(triple());
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
  } else if (MCPU.empty() && Obj->getArch() == Triple::aarch64) {
    Features.AddFeature("+all");
  }

  if (MCPU.empty())
    MCPU = Obj->tryGetCPUName().value_or("").str();

  if (isArmElf(*Obj)) {
    // When disassembling big-endian Arm ELF, the instruction endianness is
    // determined in a complex way. In relocatable objects, AAELF32 mandates
    // that instruction endianness matches the ELF file endianness; in
    // executable images, that's true unless the file header has the EF_ARM_BE8
    // flag, in which case instructions are little-endian regardless of data
    // endianness.
    //
    // We must set the big-endian-instructions SubtargetFeature to make the
    // disassembler read the instructions the right way round, and also tell
    // our own prettyprinter to retrieve the encodings the same way to print in
    // hex.
    const auto *Elf32BE = dyn_cast<ELF32BEObjectFile>(Obj);

    if (Elf32BE && (Elf32BE->isRelocatableObject() ||
                    !(Elf32BE->getPlatformFlags() & ELF::EF_ARM_BE8))) {
      Features.AddFeature("+big-endian-instructions");
      ARMPrettyPrinterInst.setInstructionEndianness(endianness::big);
    } else {
      ARMPrettyPrinterInst.setInstructionEndianness(endianness::little);
    }
  }

  DisassemblerTarget PrimaryTarget(TheTarget, *Obj, TripleName, MCPU, Features);

  // If we have an ARM object file, we need a second disassembler, because
  // ARM CPUs have two different instruction sets: ARM mode, and Thumb mode.
  // We use mapping symbols to switch between the two assemblers, where
  // appropriate.
  std::optional<DisassemblerTarget> SecondaryTarget;

  if (isArmElf(*Obj)) {
    if (!PrimaryTarget.SubtargetInfo->checkFeatures("+mclass")) {
      if (PrimaryTarget.SubtargetInfo->checkFeatures("+thumb-mode"))
        Features.AddFeature("-thumb-mode");
      else
        Features.AddFeature("+thumb-mode");
      SecondaryTarget.emplace(PrimaryTarget, TripleName, MCPU, Features);
    }
  } else if (const auto *COFFObj = dyn_cast<COFFObjectFile>(Obj)) {
    const chpe_metadata *CHPEMetadata = COFFObj->getCHPEMetadata();
    if (CHPEMetadata && CHPEMetadata->CodeMapCount) {
      // Set up x86_64 disassembler for ARM64EC binaries.
      Triple X64Triple(TripleName);
      X64Triple.setArch(Triple::ArchType::x86_64);

      std::string Error;
      const Target *X64Target =
          TargetRegistry::lookupTarget("", X64Triple, Error);
      if (X64Target) {
        SubtargetFeatures X64Features;
        SecondaryTarget.emplace(X64Target, *Obj, X64Triple.getTriple(), "",
                                X64Features);
      } else {
        reportWarning(Error, Obj->getFileName());
      }
    }
  }

  using SymbolRef = object::SymbolRef;
  // load text relocations
  std::map<uint64_t, object::RelocationRef> relocs;
  auto textname = textSectName();
  textsecti_ = 0;
  for (auto &s : ofile_->sections()) {
    auto expName = s.getName();
    if (!expName || textname != expName->data()) {
      textsecti_++;
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
        relocs.insert({r.getOffset(), r});
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
  for (auto opc = textvm_, opcend = textvm_ + textsz_; opc < opcend;) {
    uint64_t size = 0;
    auto status = PrimaryTarget.DisAsm->getInstruction(
        inst, size, BuildIDRef(reinterpret_cast<const uint8_t *>(opc), 16), opc,
        outs());
    InsnInfo iinfo{};
    iinfo.rva = vm2rva(opc);
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
        auto expType = sym->getType();
        auto expFlags = sym->getFlags();
        if (!expName || !expType || !expFlags) {
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
        if (rit == irelocs_.end()) {
          if (expFlags.get() & SymbolRef::SF_Undefined) {
            // locate and insert a new extern relocation
            auto rtaddr =
                Loader::locateSymbol(name, expType.get() == SymbolRef::ST_Data);
            rit =
                irelocs_.insert(irelocs_.end(), RelocInfo{name.data(), rtaddr});
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
                                      RelocInfo{name.data(), rtaddr});
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
                                    RelocInfo{name.data(), rtaddr});
            }
          }
          log_print(Develop, "Relocated symbol {} at {}.", rit->name,
                    rit->target);
        }
        // record its relocation index
        iinfo.rflag = 1;
        iinfo.reloc = rit - irelocs_.begin();
      }
      // convert llvm opcode to icpp InsnType
      std::function<uint8_t(unsigned)> llvm2uc_register;
      if (arch() == AArch64) {
        llvm2uc_register = llvm2ucRegisterAArch64;
        parseInstAArch64(inst, opc, idecinfs_, iinfo);
      } else {
        llvm2uc_register = llvm2ucRegisterX64;
        parseInstX64(inst, opc, idecinfs_, iinfo);
      }
      // encode none-hardware instruction
      if (iinfo.type != INSN_HARDWARE) {
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
    iinfs_.push_back(iinfo);
    opc += iinfo.len;
  }
}

} // namespace icpp
