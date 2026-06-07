#include <iostream>
#include <string>
#include <cstdlib> // getenv, strtol
#include <cctype>

using namespace std;

static string url_decode(const string& s)
{
    string res;
    res.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (c == '+') {
            res += ' ';
        } else if (c == '%' && i + 2 < s.size()
                   && isxdigit(static_cast<unsigned char>(s[i+1]))
                   && isxdigit(static_cast<unsigned char>(s[i+2]))) {
            string hex = s.substr(i + 1, 2);
            char decoded = static_cast<char>(strtol(hex.c_str(), nullptr, 16));
            res += decoded;
            i += 2;
        } else {
            res += c;
        }
    }
    return res;
}

int main()
{
    cout << "Content-type:text/html\r\n\r\n";
    cout << "<html>\n";
    cout << "<head>\n";
    cout << "<title>Using GET and POST Methods</title>\n";
    cout << "</head>\n";
    cout << "<body>\n";

    const char* qs = getenv("QUERY_STRING");
    string first_name;

    if (qs) {
        string query(qs);
        size_t start = 0;
        while (start < query.size()) {
            size_t amp = query.find('&', start);
            string pair = query.substr(start, (amp == string::npos) ? string::npos : amp - start);
            size_t eq = pair.find('=');
            if (eq != string::npos) {
                string key = pair.substr(0, eq);
                string val = pair.substr(eq + 1);
                if (key == "first_name") {
                    first_name = url_decode(val);
                    break;
                }
            }
            if (amp == string::npos) break;
            start = amp + 1;
        }
    }

    if (!first_name.empty()) {
        cout << "First name: " << first_name << endl;
    } else {
        cout << "No";
    }

    cout << "\n</body>\n</html>\n";
    return 0;
}