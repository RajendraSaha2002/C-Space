#include <iostream>
using namespace std;
enum class Color
{
    Red,
    Green,
    Blue
};
int main()
{
    Color myColor=Color::Red;
    int value=static_cast<int>(myColor);
    cout<<"Integer value:"<<value<<endl;
    return 0;

}