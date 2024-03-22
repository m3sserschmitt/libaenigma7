#include "cryptography/File.hh"

const char *File::readFile(const char *path, unsigned int &len)
{
    std::string line;
    std::string content;
    std::ifstream in(path, std::ifstream::in);

    len = 0;

    if (not in.is_open())
    {
        return nullptr;
    }

    while (getline(in, line))
    {
        content += line;
    }

    len = content.size();

    char *data = new char[len + 1];
    memcpy(data, content.c_str(), content.size());
    data[len] = 0;

    return data;
}
