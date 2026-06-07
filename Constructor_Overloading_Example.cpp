#include <iostream>
using namespace std;
class Rectangle
{
    public:
    int length, width;
    Rectangle()
    {
        length =1;
        width =1;
    }
    Rectangle(int side)
    {
        length =side;
        width =side;
    }
    Rectangle(int l, int w)
    {
        length =l;
        width =w;
    }
    void displayArea()
    {
        cout<<"Area:"<<length*width<<endl;
    }
};
int main()
{
    Rectangle rect1; // Default constructor
    Rectangle rect2(5);
    Rectangle rect3(5, 3);
    rect1.displayArea();
    rect2.displayArea();
    rect3.displayArea();
    return 0;
}