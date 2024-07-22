#include <icpp.hpp>
#include <icppex.hpp>

#if __WIN__
#define arg_count "-n"s, "1"s
#else
#define arg_count "-c"s, "1"s
#endif

int main(int argc, const char *argv[]) {
  icpp::prints("Command result: {}\n",
               icppex::command("ping"s, {arg_count, "vpand.com"s}));
  return 0;
}
