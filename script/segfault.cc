int main(int argc, const char *argv[]) {
  // trigger a segment fault on purpose
  *reinterpret_cast<char *>(argc) = 0;
  return 0;
}
