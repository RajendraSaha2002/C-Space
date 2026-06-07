#include <iostream>
using namespace std;
int main()
{
    cout<<"Set-Cookie:User ID=XYZ;\r\n";
    cout<<"Set-Cookie:Password=XYZ123;\r\n";
    cout<<"Set-Cookie:Domain=www.google.com;\r\n";
    cout<<"Set-Cookie:Path=/perl;\n";
    cout<<"Context-type:text/html\r\n\r\n";
    cout<<"<html>\n";
    cout<<"<head>\n";
    cout<<"<title>Cookies in CGI</title>\n";
    cout<<"</head>\n";
    cout<<"<body>\n";
    cout<<"Setting cookies"<<endl;
    cout<<"br/n";
    cout<<"</body>\n";
    cout<<"</html>\n";
    return 0;
}