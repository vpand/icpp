#include <iostream>

class ctor_t {
public:
  // const char * exception
  ctor_t() { throw "This is a 'const char *' exception."; }

  void hello() { puts("Hello, world."); }
} ctor;

int main(int argc, const char *argv[]) {
  try {
    if (argc == 1) {
      ctor.hello();
      // std::exception
      // when hit this line, icpp will stop interpreting current function.
      throw std::invalid_argument("This is an 'std::exception' exception.");
    }
    std::cout << "The argv[1] is " << argv[1] << std::endl;
  } catch (...) {
    // icpp doesn't support interpreting catch block currently,
    // this line will be definitely ignored even if exception thrown.
    std::cout << "Will never reach here..." << std::endl;
  }
  return 0;
}
