//===-- C standard library header stdio.h ---------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIBC_STDIO_H
#define LLVM_LIBC_STDIO_H

#include "__llvm-libc-common.h"
#include "llvm-libc-macros/file-seek-macros.h"
#include "llvm-libc-macros/stdio-macros.h"

#include <stdarg.h>

#define _IONBF 2

#define stdout stdout

#define stderr stderr

#define _IOLBF 1

#define stdin stdin

#define _IOFBF 0

#include <llvm-libc-types/size_t.h>
#include <llvm-libc-types/off_t.h>
#include <llvm-libc-types/cookie_io_functions_t.h>
#include <llvm-libc-types/FILE.h>

__BEGIN_C_DECLS

int remove(const char *) __NOEXCEPT;

int rename(const char *, const char *) __NOEXCEPT;

int sprintf(char *__restrict, const char *__restrict, ...) __NOEXCEPT;

int snprintf(char *__restrict, size_t, const char *__restrict, ...) __NOEXCEPT;

int fprintf(FILE *__restrict, const char *__restrict, ...) __NOEXCEPT;

int printf(const char *__restrict, ...) __NOEXCEPT;

int vsprintf(char *__restrict, const char *__restrict, va_list) __NOEXCEPT;

int vsnprintf(char *__restrict, size_t, const char *__restrict, va_list) __NOEXCEPT;

int vfprintf(FILE *__restrict, const char *__restrict, va_list) __NOEXCEPT;

int vprintf(const char *__restrict, va_list) __NOEXCEPT;

int sscanf(const char *__restrict, const char *__restrict, ...) __NOEXCEPT;

int scanf(const char *__restrict, ...) __NOEXCEPT;

int fscanf(FILE *__restrict, const char *__restrict, ...) __NOEXCEPT;

int fileno(FILE *) __NOEXCEPT;

FILE * fdopen(int, const char *) __NOEXCEPT;

void clearerr(FILE *) __NOEXCEPT;

void clearerr_unlocked(FILE *) __NOEXCEPT;

int fclose(FILE *) __NOEXCEPT;

void flockfile(FILE *) __NOEXCEPT;

int feof(FILE *) __NOEXCEPT;

int feof_unlocked(FILE *) __NOEXCEPT;

int ferror(FILE *) __NOEXCEPT;

int ferror_unlocked(FILE *) __NOEXCEPT;

int fgetc(FILE *) __NOEXCEPT;

int fgetc_unlocked(FILE *) __NOEXCEPT;

char * fgets(char *__restrict, int, FILE *__restrict) __NOEXCEPT;

int fflush(FILE *) __NOEXCEPT;

FILE * fopen(const char *, const char *) __NOEXCEPT;

int fputc(int, FILE *) __NOEXCEPT;

int fputs(const char *__restrict, FILE *__restrict) __NOEXCEPT;

FILE * fopencookie(void *, const char *, cookie_io_functions_t) __NOEXCEPT;

size_t fread(void *__restrict, size_t, size_t, FILE *__restrict) __NOEXCEPT;

size_t fread_unlocked(void *__restrict, size_t, size_t, FILE *__restrict) __NOEXCEPT;

int fseek(FILE *, long, int) __NOEXCEPT;

long ftell(FILE *) __NOEXCEPT;

void funlockfile(FILE *) __NOEXCEPT;

size_t fwrite(const void *__restrict, size_t, size_t, FILE *__restrict) __NOEXCEPT;

size_t fwrite_unlocked(const void *__restrict, size_t, size_t, FILE *__restrict) __NOEXCEPT;

int getc(FILE *) __NOEXCEPT;

int getc_unlocked(FILE *) __NOEXCEPT;

int getchar(void) __NOEXCEPT;

int getchar_unlocked(void) __NOEXCEPT;

int putc(int, FILE *) __NOEXCEPT;

int putchar(int) __NOEXCEPT;

int puts(const char *__restrict) __NOEXCEPT;

void setbuf(FILE *__restrict, char *__restrict) __NOEXCEPT;

int setvbuf(FILE *__restrict, char *__restrict, int, size_t) __NOEXCEPT;

int ungetc(int, FILE *) __NOEXCEPT;

extern FILE * stderr;
extern FILE * stdin;
extern FILE * stdout;
__END_C_DECLS

#endif // LLVM_LIBC_STDIO_H
