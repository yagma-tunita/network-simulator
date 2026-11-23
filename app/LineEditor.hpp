#pragma once

#include <functional>
#include <string>
#include <vector>

namespace LineEditor
{
    using Completer = std::function<std::vector<std::string>(const std::string &)>;

    void SetCompleter(Completer fn);
    bool ReadLine(const std::string &prompt, std::string &out);
    void AddHistory(const std::string &line);
    void LoadHistory(const std::string &path);
    void SaveHistory(const std::string &path);
}
