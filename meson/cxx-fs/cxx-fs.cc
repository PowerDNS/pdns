#include <filesystem>

int main()
{
  std::filesystem::path path(".");
  [[maybe_unused]] std::filesystem::file_status status = std::filesystem::status(path);
  return 0;
}
