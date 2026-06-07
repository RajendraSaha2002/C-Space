#include <iostream>
using namespace std;
int main()
{
    int a=16;
    short int b=3;
    long int c=-32;
    long long int d=555;
    unsigned short int e=22;
    unsigned int f=33;
    unsigned long int g=888;
    unsigned long long int h=444444;
    cout<<"sizeof int datatype is:"<<sizeof(a)<<"and the number is:"<<a<<endl;
    cout<<"sizeof short int datatyoe is:"<<sizeof(unsigned int)<<"and the number is:"<<b<<endl;
    cout<<"sizeof long int datatype is:"<<sizeof(short int)<<"and the number is:"<<c<<endl;
    cout<<"sizeof long long int datatype is:"<<sizeof(unsigned short int)<<"and the number is:"<<d<<endl;
    cout<<"sizeof unsigned short int datatype is:"<<sizeof(long int)<<"and the number is:"<<e<<endl;
    cout<<"sizeof unsigned int datatype is:"<<sizeof(long long int)<<"and the number is:"<<g<<endl;
    cout<<"sizeof unsigned long long int datatype is:"<<sizeof(unsigned long long int)<<"and the number is:"<<h<<endl;
    return 0;
    

}