#include <iostream>

int main(int argc, const char *argv[]) {
  try {
    if (argc == 1) {
      // when hit this line, icpp will stop interpreting.
      throw "Threw this exception because of argc is 1.";
    }
    std::cout << "The argv[1] is " << argv[1] << std::endl;
  } catch (...) {
    // icpp doesn't support interpreting catch block currently,
    // this line will be definitely ignored even if exception thrown.
    std::cout << "Will never reach here..." << std::endl;
  }
  return 0;
}
