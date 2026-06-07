#include <iostream>
using namespace std;
class Shape
{
    public:
    virtual int getArea()=0;
    void setWidth(int w)
    {
        width=w;
    }
    void setHeight(int h)
    {
        height=h;
    }
    protected:
    int width;
    int height;
};
class Rectangle:public Shape{
    public:
    int getArea()
    {
        return (width*height);
    }
};
class Tringle:public Shape{
    public:
    int getArea()
    {
        return (width*height)/2;
    }
};
int main()
{
    Rectangle Rect;
    Tringle Tri;
    Rect.setWidth(5);
    Rect.setHeight(7);
    cout<<"Total Rectangle area:"<<Rect.getArea()<<endl;
    Tri.setWidth(5);
    Tri.setHeight(7);
    cout<<"Total Tringle area:"<<Tri.getArea()<<endl;
    return 0;
}