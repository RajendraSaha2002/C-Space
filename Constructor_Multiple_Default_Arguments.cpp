#include <iostream>
using namespace std;
class Box
{
    public:
    int length, width, heigth;
    Box(int l=5, int w=10, int h=2)
    {
        length =l;
        width =w;
        heigth =h;
    }
    void display()
    {
        cout<<"length:"<<length<<", Width:"<<width<<", Height:"<<heigth<<endl;
    }
};
int main()
{
    Box box1;
    Box box2(15);
    Box box3(15, 20);
    Box box4(15, 20, 25);
    box1.display();
    box2.display();
    box3.display();
    box4.display();
    return 0;
}