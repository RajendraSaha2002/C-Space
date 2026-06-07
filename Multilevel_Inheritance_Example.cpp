#include <iostream>
using namespace std;
class Shape
{
    public:
    void display()
    {
        cout<<"This is a shape."<<endl;
    }
};
class Polygon: public Shape
{
    public:
    void sides()
    {
        cout<<"A polygon has multiple sides."<<endl;
    }
};
class Trinagle: public Polygon
{
    public:
    void type()
    {
        cout<<"A tringle comes under a three-sided polygon."<<endl;
    }
};
int main()
{
    Trinagle myTringle;
    myTringle.display();
    myTringle.sides();
    return 0;
}