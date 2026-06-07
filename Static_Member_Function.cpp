#include <iostream>
using namespace std;
class Myclass
{
    public:
    static void displayMessage()
    {
        cout<<"Hello, World!";
    }
};
int main()
{
    Myclass::displayMessage();
    return 0;
}
