#include <bits/stdc++.h>
using namespace std;
void printvector(vector <int>&v)
{
    for_each(v.begin(),v.end(),[](int i)
    {
std::cout<<i<<"";
    });
    cout<<endl;
}
int main()
{
    vector<int>v;
    v.push_back(10);
    v.push_back(11);
    v.push_back(12);
    printvector(v);
    return 0;
}