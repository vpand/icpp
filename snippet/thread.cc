#include <chrono>
#include <cstdio>
#include <thread>

void thread_proc(int number) {
  for (size_t i = 0; i < 10; i++) {
    std::printf("Printed in new thread #%d.\n", number);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
  }
}

int main(int argc, const char *argv[]) {
  int threads = 6;
  if (argc > 1) {
    auto usrdef = std::atoi(argv[argc - 1]);
    if (usrdef)
      threads = usrdef;
  }

  std::thread **ths = new std::thread *[threads];
  std::printf("Create and run %d threads...\n", threads);
  for (int i = 0; i < threads; i++)
    ths[i] = new std::thread(thread_proc, 1 + i);
  for (int i = 0; i < threads; i++) {
    ths[i]->join();
    delete ths[i];
  }
  delete[] ths;
  std::puts("Done.");
  return 0;
}
