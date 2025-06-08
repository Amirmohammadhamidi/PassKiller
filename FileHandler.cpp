#include <iostream>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>
#include <fstream>
#include <map>

using namespace std;

std::map<std::string, std::string> commands;

void initialize()
{
    generate_commands_map();
}

void generate_commands_map()
{
    commands["py"] = "python3 ";
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

std::string runPython(const std::string &file_path)
{
    std::string result;
    char buffer[128];

    // run python script
    string command = get_command("py", file_path);
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

std::string run_file(const std::string &file_path)
{
    if (!fileExists(file_path))
    {
        return "file not found!";
    }

    string type = getExtension(file_path);
    if (type == "py")
        return runPython(file_path);

    return "Unsupported file type!";
}