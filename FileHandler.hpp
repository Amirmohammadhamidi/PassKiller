#ifndef FileHandler_hpp
#define FileHandler_hpp
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>
#include <fstream>
#include <map>
#include <filesystem>
#include <vector>
#include <algorithm>

using namespace std;
namespace fs = std::filesystem;

class FileHandler
{
private:
    const std::vector<std::string> extensions = {"py"};
    const std::map<std::string, std::string> commands = {
        {"py", "python3 -u "}};

public:
    std::string get_project_path() { return fs::current_path().string(); };
    bool fileExists(const string &filename);
    string getExtension(const string &filename);
    bool extension_valid(const string &extension);
    std::string get_command(const string &extension, const string &file_path);
    std::string runfile(const string &file_path, const vector<std::string> &args);
    std::string runPython(const string &file_path, const vector<std::string> &args);
};
#endif