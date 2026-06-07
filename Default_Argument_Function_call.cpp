#include <iostream>
#include <cmath>
using namespace std;
double getDefaultWidth()
{
    return 5.0;
}
double getDefaultRadius()
{
    return 3.0;
}
double cuboid_vol(double l, double h, double w =getDefaultWidth())
{
    return l*w*h;
}
double cylinder_vol(double h, double r =getDefaultRadius())
{
    return M_PI*r*r*h;
}
int main()
{
    double length = 10.0;
    double heigth = 7.0;
    cout<<"Cuboid volume:"<<cuboid_vol(length, heigth)<<"cubic units"<<endl;
    cout<<"cuboid volume(custom width):"<<cuboid_vol(length, heigth, 4.0)<<"cubic units"<<endl;
    cout<<"Cylinder volume(default radius):"<<cylinder_vol(heigth, 6.0)<<"cubic units"<<endl;
    return 0;
}