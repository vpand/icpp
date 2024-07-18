#include <icpp.hpp>

int main(int argc, const char *argv[]) {
  auto msg = "Hello, world. Nice to meet you. Have a nice day. Good bye."s;
  auto results = icpp::split(msg, ". ");
  icpp::prints("Original: {}\nSplits:\n", msg);
  for (auto &s : results) {
    icpp::prints("\t{}\n", s);
  }
  return 0;
}
