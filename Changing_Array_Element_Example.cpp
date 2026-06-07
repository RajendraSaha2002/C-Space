#include <iostream>
using namespace std;
int main()
{
    int arr[]={10, 20, 30, 40, 50};
    cout<<"Before changing element at index 2:"<<arr[2]<<endl;
    arr[2]=108;
    cout<<"After changing, element at index 2:"<<arr[2]<<endl;
    return 0;
}