#include <cstdio>
#include <thread>

void thread_proc(const char *program) {
  std::printf("Printed in a new thread: %s\n", program);
}

int main(int argc, const char *argv[]) {
  std::puts("Creating a new thread.");
  std::thread(thread_proc, argv[0]).join();
  std::puts("Done.");
  return 0;
}
