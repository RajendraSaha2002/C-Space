#include <iostream>
using namespace std;
class Shape
{
    public:virtual void draw()=0;
    virtual~Shape(){}
};
class Circle:public Shape{
    public:void draw() override
    {
        cout<<"Drawing Circle"<<endl;
    }
};
class Rectangle:public Shape{
    public:void draw() override
    {
        cout<<"Drawing Rectangle"<<endl;
    }
};
class Tringle:public Shape{
    public:void draw() override
    {
        cout<<"Drawing Tringle"<<endl;
    }
};
int main()
{
    Shape*shapes[]=
    {
        new Circle(),
        new Rectangle(),
        new Tringle()
    };
    for(Shape*shape:shapes)
    {
        shape->draw();
    }
    for(Shape*shape:shapes)
    {
        delete shape;
    }
    return 0;
}