int main(int argc, const char *argv[]) {
  // trigger a segment fault on purpose
  *reinterpret_cast<char *>(0x100000000) = 0;
  return 0;
}
