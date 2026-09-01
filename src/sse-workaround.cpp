/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under GPLv2.
   See LICENSE in root directory for more details
*/

#pragma once

namespace {

// workaround for the SSE instruction emulation in unicorn engine, as the
// unicorn engine has bug on the SSE instructions, we need to emulate them
// manually.
enum class PackedDoubleOp { Add, Mul, Sub, Div, Unknown };

static PackedDoubleOp classifyOpcodeByte(uint8_t op) {
  switch (op) {
  case 0x58:
    return PackedDoubleOp::Add; // ADDPD
  case 0x59:
    return PackedDoubleOp::Mul; // MULPD
  case 0x5C:
    return PackedDoubleOp::Sub; // SUBPD
  case 0x5E:
    return PackedDoubleOp::Div; // DIVPD
  default:
    return PackedDoubleOp::Unknown;
  }
}

static constexpr uc_x86_reg kXmmRegs[16] = {
    UC_X86_REG_XMM0,  UC_X86_REG_XMM1,  UC_X86_REG_XMM2,  UC_X86_REG_XMM3,
    UC_X86_REG_XMM4,  UC_X86_REG_XMM5,  UC_X86_REG_XMM6,  UC_X86_REG_XMM7,
    UC_X86_REG_XMM8,  UC_X86_REG_XMM9,  UC_X86_REG_XMM10, UC_X86_REG_XMM11,
    UC_X86_REG_XMM12, UC_X86_REG_XMM13, UC_X86_REG_XMM14, UC_X86_REG_XMM15,
};

bool interpretPackedDoubleOp(uc_engine *uc, const uint8_t *opcode) {
  size_t i = 0;

  // Mandatory 66 prefix.
  if (opcode[i] != 0x66)
    return false;
  ++i;

  // Optional REX prefix (0x40-0x4F): sits between 66 and 0F.
  uint8_t rex = 0;
  bool has_rex = false;
  if ((opcode[i] & 0xF0) == 0x40) {
    rex = opcode[i];
    has_rex = true;
    ++i;
  }

  // Two-byte opcode escape.
  if (opcode[i] != 0x0F)
    return false;
  ++i;

  const PackedDoubleOp op = classifyOpcodeByte(opcode[i]);
  if (op == PackedDoubleOp::Unknown)
    return false;
  ++i;

  const uint8_t modrm = opcode[i++];
  const uint8_t mod = (modrm >> 6) & 0x3;
  const uint8_t reg = (modrm >> 3) & 0x7;
  const uint8_t rm = modrm & 0x7;

  const bool rex_r = has_rex && (rex & 0x4); // REX.R: extends reg field
  const bool rex_b = has_rex && (rex & 0x1); // REX.B: extends rm field

  const int dst_index = reg + (rex_r ? 8 : 0);

  uint8_t dst[16];
  uc_reg_read(uc, kXmmRegs[dst_index], dst);
  auto dst_lanes = reinterpret_cast<double *>(dst);
  auto src_lanes = reinterpret_cast<const double *>(opcode - 0x10);

  for (int lane = 0; lane < 2; ++lane) {
    switch (op) {
    case PackedDoubleOp::Add:
      dst_lanes[lane] += src_lanes[lane];
      break;
    case PackedDoubleOp::Mul:
      dst_lanes[lane] *= src_lanes[lane];
      break;
    case PackedDoubleOp::Sub:
      dst_lanes[lane] -= src_lanes[lane];
      break;
    case PackedDoubleOp::Div:
      dst_lanes[lane] /= src_lanes[lane];
      break;
    default:
      break;
    }
  }

  uc_reg_write(uc, kXmmRegs[dst_index], dst);
  return true;
}

} // namespace
