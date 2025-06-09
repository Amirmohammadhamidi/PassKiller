#include <iostream>
#include "FileHandler.hpp"

using namespace std;
namespace fs = std::filesystem;

bool FileHandler::fileExists(const std::string &filename)
{
    ifstream file(filename);
    return file.good();
}

string FileHandler::getExtension(const std::string &filename)
{
    return fs::path(filename).extension().string().substr(1);
}

bool FileHandler::extension_valid(const string &extension)
{
    return find(extensions.begin(), extensions.end(), extension) != extensions.end();
}

std::string FileHandler::get_command(const std::string &extension, const std::string &file_path)
{
    return commands.at(extension) + file_path;
}

std::string FileHandler::runPython(const std::string &file_path, const std::vector<std::string> &args)
{
    std::string result;
    char buffer[128];

    string command = get_command("py", file_path);
    for (const auto &arg : args)
    {
        command += " " + arg;
    }

    std::shared_ptr<FILE> pipe(popen(command.c_str(), "r"), pclose);
    if (!pipe)
        throw std::runtime_error("popen() failed!");

    while (fgets(buffer, sizeof(buffer), pipe.get()) != nullptr)
    {
        result += buffer;
    }

    return result;
}

std::string FileHandler::runfile(const std::string &file_path, const std::vector<std::string> &args)
{
    if (!fileExists(file_path))
    {
        return "file not found!";
    }

    string type = getExtension(file_path);
    if (extension_valid(type))
    {
        if (type == "py")
            return runPython(file_path, args);
        else
            return "Unsupported file type!";
    }
    else
        return "Unsupported file type!";
}
