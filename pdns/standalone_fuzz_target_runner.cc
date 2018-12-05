
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <sys/stat.h>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);
extern "C" __attribute__((weak)) int LLVMFuzzerInitialize(int* argc, char*** argv);

int main(int argc, char** argv)
{
  std::cerr<<"StandaloneFuzzTargetMain: running "<<(argc-1)<<" inputs"<<std::endl;

  if (LLVMFuzzerInitialize) {
    LLVMFuzzerInitialize(&argc, &argv);
  }

  for (int i = 1; i < argc; i++) {

    struct stat st;
    if (stat(argv[i], &st) || !S_ISREG(st.st_mode)) {
      std::cerr<<"Skipping non-regular file: "<<std::string(argv[i])<<std::endl;
      continue;
    }

    std::cerr<<"Running: "<<std::string(argv[i])<<std::endl;

    std::ifstream file(argv[i], std::ios::binary);
    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<char> buffer;
    buffer.resize(fileSize);

    file.read(reinterpret_cast<char*>(buffer.data()), fileSize);

    if (file.fail()) {
      file.close();
      throw std::runtime_error("Error reading fuzzing input from file '" + std::string(argv[i]) + '"');
    }

    file.close();

    LLVMFuzzerTestOneInput(reinterpret_cast<const uint8_t*>(buffer.data()), fileSize);

    std::cerr<<"Done: '"<<std::string(argv[i])<<"': ("<<fileSize<<" bytes)"<<std::endl;
  }

  return 0;
}
