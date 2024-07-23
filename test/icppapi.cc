#include <icpp.hpp>

int main(int argc, const char *argv[]) {
  auto thisdir = fs::path(argv[0]).parent_path();

  icpp::prints("The running {} version is {}.\nCurrent user home is {}.\n",
               icpp::program(), icpp::version(), icpp::home_directory());

  icpp::prints("The {} is a c++ source? {}.\n", argv[0],
               icpp::is_cpp_source(argv[0]));

  icpp::prints("Random values: {}, {}, {}.\n", icpp::rand_value(),
               icpp::rand_string(16), icpp::rand_filename(8, ".cc"));

  std::puts("Executing a c code...");
  icpp::exec_string("#include <stdio.h>\n"
                    "int main() {"
                    "puts(\"Hello world from c.\");"
                    "return 0;"
                    "}");

  std::puts("Executing a c++ expression...");
  icpp::exec_expression("icpp::result_set(88888888)");
  icpp::prints("Current result: i={}\n", icpp::result_get());

  std::puts("Executing a c++ code...");
  icpp::exec_string("#include <icpp.hpp>\n"
                    "int main(int argc, const char *argv[]) {"
                    "std::puts(\"Executing string...\");"
                    "icpp::result_set(argv[0]);"
                    "std::puts(\"Done.\");"
                    "return 0;"
                    "}",
                    argc, argv);
  icpp::prints("Current result: s={}\n", icpp::result_gets());

  std::puts("Executing a c++ source...");
  icpp::exec_source((thisdir / "split.cc").string());

  std::puts("Executing a icpp module...");
  icpp::exec_module("module-demo");

  if (argc == -1) {
    icpp::result_set(0);
    icpp::result_set("");
    icpp::load_library("");
    icpp::unload_library(nullptr);
    icpp::resolve_symbol("");
    icpp::iterate_modules(
        [](uint64_t base, std::string_view path) { return true; });
  }

  return 0;
}
