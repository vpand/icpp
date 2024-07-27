import std;

std::string_view __attribute__((noinline)) message(std::string_view init) {
  static std::string msg{init};
  return msg;
}

int main(void) {
  std::puts(message("Hello world.").data());
  std::puts(message("Hello icpp.").data());
  return 0;
}
