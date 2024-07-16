import std;

int main(int argc, const char *argv[]) {
  constexpr const int number = 88888888;
  std::cout << std::format("The hexadecimal of {} is 0x{:x}.", number, number)
            << std::endl;
  return 0;
}
