#ifndef FILE_HH
#define FILE_HH

#include <fstream>
#include <string>
#include <cstring>

class File
{
public:
    static const char *readFile(const char *path, Size &len)
    {
        std::string line;
        std::string content;
        std::ifstream in(path, std::ifstream::in);
        
        len = 0;

        if(not in.is_open())
        {
            return nullptr;
        }

        while(getline(in, line))
        {
            content += line;
        }

        len = content.size();

        char *data = new char[len + 1];
        strcpy(data, content.c_str());
        data[len] = 0;

        return data;
    }
};

#endif