/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include <Windows.h>
#include <stdio.h>

// tried to build the libc++abi on windows, but failed, and boost libraries
// depend on it, herein give it a simple implementation
__declspec(dllexport) char *__cxa_demangle(const char *MangledName, char *Buf,
                                           size_t *N, int *Status) {
  Status = 0;
  *N = snprintf(Buf, *N, "%s", MangledName);
  return Buf;
}

/*
implement the unresolved symbols when linking boost libraries on windows
*/

#undef InterlockedCompareExchange
__declspec(dllexport) LONG InterlockedCompareExchange(
    LONG volatile *Destination, LONG ExChange, LONG Comperand) {
  return _InterlockedCompareExchange(Destination, ExChange, Comperand);
}

#undef InterlockedCompareExchangePointer
__declspec(dllexport) PVOID InterlockedCompareExchangePointer(
    PVOID volatile *Destination, PVOID Exchange, PVOID Comperand) {
  return _InterlockedCompareExchangePointer(Destination, Exchange, Comperand);
}

#undef InterlockedDecrement
__declspec(dllexport) LONG InterlockedDecrement(LONG volatile *Addend) {
  return _InterlockedDecrement(Addend);
}

#undef InterlockedIncrement
__declspec(dllexport) LONG InterlockedIncrement(LONG volatile *Addend) {
  return _InterlockedIncrement(Addend);
}

#undef InterlockedExchange
__declspec(dllexport) LONG InterlockedExchange(LONG volatile *Target,
                                               LONG Value) {
  return _InterlockedExchange(Target, Value);
}

#undef InterlockedExchangeAdd
__declspec(dllexport) LONG InterlockedExchangeAdd(LONG volatile *Addend,
                                                  LONG Value) {
  return _InterlockedExchangeAdd(Addend, Value);
}

#undef InterlockedExchangePointer
__declspec(dllexport) PVOID InterlockedExchangePointer(PVOID volatile *Target,
                                                       PVOID Value) {
  return _InterlockedExchangePointer(Target, Value);
}
