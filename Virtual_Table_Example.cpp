#include <iostream>
using namespace std;
class shape
{
    public: virtual void draw()
    {
        cout<<"Creating a shape!"<<endl;
    }
};
class circle:public shape{
    public:void draw()
    {
        cout<<"Creating a Circle!"<<endl;
    }
};
class square:public shape{
    public: void draw()
    {
        cout<<"Creating a Square!"<<endl;
    }
};
int main()
{
    shape*shapePtr;
    circle c;
    square s;
    shapePtr=&c;
    shapePtr->draw();
    shapePtr=&s;
    shapePtr->draw();
    return 0;
}