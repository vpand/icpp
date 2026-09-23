#include <icpp.hpp>

#include "aes.c"

int main(int argc, const char *argv[]) {
  std::string_view text = "AetherVM";
  char result[64];

  const auto start = std::chrono::high_resolution_clock::now();

  std::string logs;
  for (int i = 0; i < 10; i++) {
    logs += std::format("Test icpp for aes from '{}' to '{}'.\n", text,
                        test_main(text.data(), text.size(), result));
  }

  const auto end = std::chrono::high_resolution_clock::now();
  const auto elapsed_ns =
      std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
  const auto elapsed_us =
      std::chrono::duration_cast<std::chrono::duration<double, std::micro>>(
          end - start)
          .count();

  std::println("{}Execution time: {} ns ({:.3f} µs)", logs, elapsed_ns,
               elapsed_us);
  return 0;
}
