#include <bits/stdc++.h>
using namespace std;
int main()
{
  string s="I love you Suchismita !!!\0 and others";
  int count =0, i=0;
  while(s[i] !='\0')
  count++, i++;
  cout<<"Length of string s:"<<count;
  return 0;
}