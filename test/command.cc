#include <icpp.hpp>

int main(int argc, const char *argv[]) {
  icpp::prints("Command result: {}\n",
               icpp::command("echo", {"Hello"s, "world"s, "."s}));
  return 0;
}
