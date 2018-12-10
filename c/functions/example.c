#include <stdio.h>

int function1(int a, int b, const char* string)
{
  int result = a + b;
  printf("Received input: %s\n", string);
  return result;
}


int main(){
  int i = 1;
  int j = 2;
  const char* msg = "Test Message!";
  int result = function1(i, j, msg);
  printf("i + j equals %d\n", result);
  return 0;
}
