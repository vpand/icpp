#include <icpp.hpp>
#include <icppex.hpp>

int main(int argc, const char *argv[]) {
  icpp::prints("Command result: {}\n",
               icppex::execute(icpp::program().data(), {"-version"s}));
  return 0;
}
