// This one can have multiple passwords

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void no()
{
    puts("Nope.");
    exit(1);
}

void ok()
{
    puts("Good job.");
    return ;
}

int main() {
    char input[24];

    printf("Please enter key: ");
    if (scanf("%23s", input) != 1 || input[1] != '0' || *input != '0')
        no();
    size_t input_len = strlen(input);
    size_t current = 2;
    char result[9] = "d";
    int i = 1;

    while(i < 8 && current + 2 < input_len)
    {
        char chunk[4] = {
            input[current],
            input[current+1],
            input[current+2],
            '\0'
        };
        result[i++] = atoi(chunk);
        current += 3;
    }

    result[i] = '\0';
    if (strcmp(result, "delabere"))
            no();
    ok();
}
