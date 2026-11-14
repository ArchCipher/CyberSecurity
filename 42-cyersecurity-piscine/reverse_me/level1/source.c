#include <stdio.h>
#include <string.h>

int main(void)
{
  char input [100];
  
  printf("Please enter key: ");
  if (scanf("%99s", input) == 1 && !strcmp(input,"__stack_check"))
    printf("Good job.\n");
  else
    printf("Nope.\n");
}
