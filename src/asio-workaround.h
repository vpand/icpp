/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under GPLv2.
   See LICENSE in root directory for more details
*/

#pragma once

#ifdef _WIN32

#define placeholders placeholders_icpp

namespace std {
namespace placeholders {

template <int _Np> struct __ph {};

// To fix: boost/asio/placeholders.hpp(62,24): error: constexpr variable 'error'
// must be initialized by a constant expression
constexpr __ph<1> _1;
constexpr __ph<2> _2;
constexpr __ph<3> _3;
constexpr __ph<4> _4;
constexpr __ph<5> _5;
constexpr __ph<6> _6;
constexpr __ph<7> _7;
constexpr __ph<8> _8;
constexpr __ph<9> _9;
constexpr __ph<10> _10;

} // namespace placeholders
} // namespace std

#endif // end of ON_WINDOWS

#include <boost/asio.hpp>

#ifdef _WIN32
#undef placeholders
#endif
