#include <iostream>
using namespace std;
int main()
{
    int arr[]={10, 20, 30, 40, 50};
    int arr_length=sizeof(arr)/sizeof(arr[0]);
    cout<<"Array's Length:"<<arr_length;
    return 0;
}