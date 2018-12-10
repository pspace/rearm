#include <stdio.h>

int main(){
  int i = 1;
  int j = 2;
  int result = i+j;

  switch(result) {
  	case 1: printf("i+j = 1\n"); break;
  	case 2: printf("i + j = 2\n"); break;
  	case 3: printf("i + j = 3\n"); break;
  	default: printf("i + j = %d\n", result); break;
  }

  i = 4;
  j = 3;
  result = i + j;
  switch(result) {
  	case 1: printf("i+j = 1\n"); break;
  	case 2: printf("i + j = 2\n"); break;
  	case 3: printf("i + j = 3\n"); break;
  	default: printf("i + j = %d\n", result); break;
  }
}
