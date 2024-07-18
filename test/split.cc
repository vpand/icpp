#include <icpp.hpp>

int main(int argc, const char *argv[]) {
  auto results = icpp::split(
      "Hello, world. Nice to meet you. Have a nice day. Good bye.", ". ");
  for (auto s : results) {
    std::prints("{}\n", s);
  }
  return 0;
}
