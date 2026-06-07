#include <iostream>
using namespace std;
class Rectangle
{
    public:
    int width, height;
    Rectangle(int w, int h): width(w), height(h){}
    void display()
    {
        cout<<"Width:"<<width<<",Height:"<<height<<endl;
    }
};
int main()
{
    Rectangle* rect = new Rectangle(10, 5);
    rect -> display();
    delete rect;
    return 0;
}