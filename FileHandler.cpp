#include <iostream>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>
#include <fstream>
#include <map>
#include <filesystem>
#include <vector>

using namespace std;
namespace fs = std::filesystem;

std::string project_path;
std::map<std::string, std::string> commands;

void set_project_path()
{
    project_path = fs::current_path().string();
}

std::string get_project_path()
{
    return project_path;
}

void generate_commands_map()
{
    commands["py"] = "python3 -u ";
}
void initialize()
{
    generate_commands_map();
    set_project_path();
}

std::string get_command(const std::string &extension, const std::string &file_path)
{
    string command = commands[extension];
    command += file_path;
    return command;
}

bool fileExists(const std::string &filename)
{
    std::ifstream file(filename);
    return file.good();
}

std::string getExtension(const std::string &filename)
{
    size_t pos = filename.find_last_of(".");
    if (pos == std::string::npos)
        return "";
    return filename.substr(pos + 1);
}

std::string runPython(const std::string &file_path, const std::vector<std::string> &args = {})
{
    std::string result;
    char buffer[128];

    // gernate command
    string command = get_command("py", file_path);
    for (const auto &arg : args)
    {
        command += " " + arg;
    }
    // run command
    std::shared_ptr<FILE> pipe(popen(command.c_str(), "r"), pclose);
    if (!pipe)
        throw std::runtime_error("popen() failed!");

    // Read the output
    while (fgets(buffer, sizeof(buffer), pipe.get()) != nullptr)
    {
        result += buffer;
    }

    return result;
}

std::string run_file(const std::string &file_path, const std::vector<std::string> &args = {})
{
    if (!fileExists(file_path))
    {
        return "file not found!";
    }

    string type = getExtension(file_path);
    if (type == "py")
        return runPython(file_path, args);

    return "Unsupported file type!";
}

int main()
{
    initialize();
    const string file_path = "/home/amirmohammad-hamidi/Desktop/PassKiller/HASH/hash-id.py";
    const std::vector<std::string> args = {"49f68a5c8493ec2c0bf489821c21fc3b"};
    string output = run_file(file_path, args);

    std::cout << output;
}