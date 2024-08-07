/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

// hit condition, see IntelArch.pdf/Page-588
#define flags context->rflags.bit

static inline int cond_hit_ja(ContextX64 *context) {
  // Jump if above (CF=0 and ZF=0).
  return flags.CF == 0 && flags.ZF == 0;
}

static inline int cond_hit_jge(ContextX64 *context) {
  // Jump if greater or equal (SF=OF).
  return flags.SF == flags.OF;
}

static inline int cond_hit_jb(ContextX64 *context) {
  // Jump if below (CF=1).
  return flags.CF == 1;
}

static inline int cond_hit_jae(ContextX64 *context) {
  // Jump if above or equal (CF=0).
  return flags.CF == 0;
}

static inline int cond_hit_je(ContextX64 *context) {
  // Jump if equal (ZF=1).
  return flags.ZF == 1;
}

static inline int cond_hit_jne(ContextX64 *context) {
  // Jump if not equal (ZF=0).
  return flags.ZF == 0;
}

static inline int cond_hit_js(ContextX64 *context) {
  // Jump if sign (SF=1).
  return flags.SF == 1;
}

static inline int cond_hit_jl(ContextX64 *context) {
  // Jump if less (SF≠ OF).
  return flags.SF != flags.OF;
}

static inline int cond_hit_jle(ContextX64 *context) {
  // Jump if less or equal (ZF=1 or SF≠ OF).
  return flags.SF != flags.OF || flags.ZF == 1;
}

static inline int cond_hit_jbe(ContextX64 *context) {
  // Jump if below or equal (CF=1 or ZF=1).
  return flags.CF == 1 || flags.ZF == 1;
}

static inline int cond_hit_jg(ContextX64 *context) {
  // Jump if greater (ZF=0 and SF=OF).
  return flags.ZF == 0 && flags.SF == flags.OF;
}

static inline int cond_hit_jno(ContextX64 *context) {
  // Jump if not overflow (OF=0).
  return flags.OF == 0;
}

static inline int cond_hit_jnp(ContextX64 *context) {
  // Jump if not parity (PF=0).
  return flags.PF == 0;
}

static inline int cond_hit_jns(ContextX64 *context) {
  // Jump if not sign (SF=0).
  return flags.SF == 0;
}

static inline int cond_hit_jo(ContextX64 *context) {
  // Jump if overflow (OF=1).
  return flags.OF == 1;
}

static inline int cond_hit_jp(ContextX64 *context) {
  // Jump if parity (PF=1).
  return flags.PF == 1;
}

static inline int cond_hit_jecxz(ContextX64 *context) {
  return static_cast<int>(context->rcx) == 0;
}

static inline int cond_hit_jrcxz(ContextX64 *context) {
  return context->rcx == 0;
}

#undef flags

static bool hitCondX64(ContextX64 *context, int cond) {
  switch (cond) {
  case CONDT_jae:
    return cond_hit_jae(context);
  case CONDT_ja:
    return cond_hit_ja(context);
  case CONDT_jbe:
    return cond_hit_jbe(context);
  case CONDT_jb:
    return cond_hit_jb(context);
  case CONDT_je:
    return cond_hit_je(context);
  case CONDT_jge:
    return cond_hit_jge(context);
  case CONDT_jg:
    return cond_hit_ja(context);
  case CONDT_jle:
    return cond_hit_jle(context);
  case CONDT_jl:
    return cond_hit_jl(context);
  case CONDT_jne:
    return cond_hit_jne(context);
  case CONDT_jno:
    return cond_hit_jno(context);
  case CONDT_jnp:
    return cond_hit_jnp(context);
  case CONDT_jns:
    return cond_hit_jns(context);
  case CONDT_jo:
    return cond_hit_jo(context);
  case CONDT_jp:
    return cond_hit_jp(context);
  case CONDT_js:
    return cond_hit_js(context);
  case CONDT_jecxz:
    return cond_hit_jecxz(context);
  case CONDT_jrcxz:
    return cond_hit_jrcxz(context);
  default:
    return false;
  }
}
