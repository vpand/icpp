#include <icppex.hpp>

int main(int argc, const char *argv[]) {
  std::puts(bp::search_path("git").string().data());
  return 0;
}
