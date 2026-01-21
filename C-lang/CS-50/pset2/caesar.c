#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_TEXT_LEN 1000

// check is argument is a digit
int is_digit(char *arg) {
    if (arg[0] =='\0') return 0;
    int i=0;
    while (arg[i]) {
        if (!isdigit(arg[i])) return 0; i++;
    }
    return 1;
}

void get_input(char *p){
    printf("plaintext:  ");
    fgets(p, MAX_TEXT_LEN, stdin); //fgets(buffer, size, stdin);
    size_t len = strlen(p);
    if (len>0 && p[len-1]=='\n'){
        p[len-1]='\0';  // change \n to \0 (avoid 2 newlines being printed)
    }
}

void rotate(char *p, int k, char *c) {
    int i=0;
    while (p[i]) {
        if (isupper(p[i])) c[i] = 'A'+(p[i]-'A'+k)%26;
        else if (islower(p[i])) c[i] = 'a'+(p[i]-'a'+k)%26;
        else c[i] = p[i];
        i++;
    }
    c[i]='\0'; //null terminate to avoid garbage being printed
}

int main (int argc, char *argv[]) {
    if (argc!=2 || !is_digit(argv[1])) {
        printf("Usage: ./caesar key\n");
        return 1;
    }
    char p[MAX_TEXT_LEN];   // plaintext
    char c[MAX_TEXT_LEN];   // ciphertext
    get_input(p);           // get plaintext as input
    int k = atoi(argv[1]);  // convert string to a digit
    rotate(p, k, c);        // rotate (convert plain to cipher)
    printf("ciphertext: %s\n", c);  // print cipher
    return 0;
}
