#include <stdio.h>

int main(){
  int i = 100;
  int j = 200;
  int result = i+j;
  
  if(result < i)
  {
    printf("THEN: %d is less than %d\n", result, i);
  }
  else
  {
    printf("ELSE: %d is larger than %d\n", result, i);
  }

  if(result > j)
  {
    printf("THEN: %d is larger than %d\n", result, i);
  }
  else
  {
    printf("ELSE: %d is less than %d\n", result, i);
  }

  printf("i + j equals %d\n", result);
}
