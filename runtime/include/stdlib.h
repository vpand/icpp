//===-- C standard library header stdlib.h --------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIBC_STDLIB_H
#define LLVM_LIBC_STDLIB_H

#include "__llvm-libc-common.h"
#include "llvm-libc-macros/stdlib-macros.h"

#include <llvm-libc-types/__atexithandler_t.h>
#include <llvm-libc-types/__qsortrcompare_t.h>
#include <llvm-libc-types/__qsortcompare_t.h>
#include <llvm-libc-types/size_t.h>
#include <llvm-libc-types/lldiv_t.h>
#include <llvm-libc-types/ldiv_t.h>
#include <llvm-libc-types/__bsearchcompare_t.h>
#include <llvm-libc-types/div_t.h>

__BEGIN_C_DECLS

int abs(int) __NOEXCEPT;

int atoi(const char *) __NOEXCEPT;

double atof(const char *__restrict) __NOEXCEPT;

long atol(const char *) __NOEXCEPT;

long long atoll(const char *) __NOEXCEPT;

void * bsearch(const void *, const void *, size_t, size_t, __bsearchcompare_t) __NOEXCEPT;

div_t div(int, int) __NOEXCEPT;

long labs(long) __NOEXCEPT;

ldiv_t ldiv(long, long) __NOEXCEPT;

long long llabs(long long) __NOEXCEPT;

lldiv_t lldiv(long long, long long) __NOEXCEPT;

void qsort(void *, size_t, size_t, __qsortcompare_t) __NOEXCEPT;

void qsort_r(void *, size_t, size_t, __qsortrcompare_t, void *) __NOEXCEPT;

int rand(void) __NOEXCEPT;

void srand(unsigned int) __NOEXCEPT;

int strfromd(char *__restrict, size_t, const char *__restrict, double) __NOEXCEPT;

int strfromf(char *__restrict, size_t, const char *__restrict, float) __NOEXCEPT;

int strfroml(char *__restrict, size_t, const char *__restrict, long double) __NOEXCEPT;

double strtod(const char *__restrict, char * *__restrict) __NOEXCEPT;

float strtof(const char *__restrict, char * *__restrict) __NOEXCEPT;

long strtol(const char *__restrict, char * *__restrict, int) __NOEXCEPT;

long double strtold(const char *__restrict, char * *__restrict) __NOEXCEPT;

long long strtoll(const char *__restrict, char * *__restrict, int) __NOEXCEPT;

unsigned long strtoul(const char *__restrict, char * *__restrict, int) __NOEXCEPT;

unsigned long long strtoull(const char *__restrict, char * *__restrict, int) __NOEXCEPT;

void * malloc(size_t) __NOEXCEPT;

void * calloc(size_t, size_t) __NOEXCEPT;

void * realloc(void *, size_t) __NOEXCEPT;

void * aligned_alloc(size_t, size_t) __NOEXCEPT;

void free(void *) __NOEXCEPT;

_Noreturn void _Exit(int) __NOEXCEPT;

_Noreturn void abort(void) __NOEXCEPT;

int at_quick_exit(__atexithandler_t) __NOEXCEPT;

int atexit(__atexithandler_t) __NOEXCEPT;

_Noreturn void exit(int) __NOEXCEPT;

char * getenv(const char *) __NOEXCEPT;

_Noreturn void quick_exit(int) __NOEXCEPT;

__END_C_DECLS

#endif // LLVM_LIBC_STDLIB_H
