#include <bits/stdc++.h>
using namespace std;
void leak_func()
{
    int *p=new int(10);
    return;
}
int main()
{
    leak_func();
    return 0;
}