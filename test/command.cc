#include <icpp.hpp>
#include <icppex.hpp>

void __declspec(dllexport) test() { boost::process::codecvt(); }

int main(int argc, const char *argv[]) {
  icpp::prints("Command result: {}\n",
               icppex::command("echo", {"Hello"s, "world"s, "."s}));
  return 0;
}
