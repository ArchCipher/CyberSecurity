#include <ctype.h>
#include <stdio.h>
#include <string.h>

#define MAX_TEXT_LEN 1000

int is_unique_alpha(char *arg) {
int seen[26]={0};
while (*arg){
if (!isalpha(*arg)) return 0;   // if not alpha
char c = toupper(*arg);
if (seen[c-'A']++) return 0;    // if not unique
arg++;
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

void substitute(char *p, char *k, char *c) {
while (*p) {
if (isupper(*p)) *c = toupper(k[*p-'A']);
else if (islower(*p)) *c = tolower(k[*p-'a']);
else *c = *p;
c++;    // move cipher pointer
p++;    // move plain pointer
}
*c='\0';        // null terminate cipher
}

int main (int argc, char *argv[]) {
    if (argc!=2 || !is_unique_alpha(argv[1]) || strlen(argv[1])!=26) {
        printf("Usage: ./substitution 26_unique_alphakey\n");
        return 1;
    }
    char p[MAX_TEXT_LEN];   // plaintext
    char c[MAX_TEXT_LEN];   // ciphertext
    get_input(p);           // get plaintext as input
    char *k = argv[1];      // new pointer for argv[1]
    substitute(p, k, c);    // substitute using key
    printf("ciphertext: %s\n", c);  // print cipher
    return 0;
}
