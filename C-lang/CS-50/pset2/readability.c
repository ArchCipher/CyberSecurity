#include <ctype.h>
#include <math.h>
#include <stdio.h>

void get_text(char *text) {
    printf("Enter text: ");
    scanf("%[^\n]%*c", text);
}

void parse_text(char *text, int *l, int *w, int *s) {
    int in_word = 0; // declare flag outside the loop
    for (int i=0; text[i]; i++) {
        if (isalpha(text[i])) (*l)++;
        if (isspace(text[i])) {
            in_word = 0; // reset when space is encountered
        }
        else if (!in_word) {
            in_word = 1; // start of a new word
            (*w)++;
        }
        if (text[i] == '.' || text[i] == '!' || text[i] == '?') (*s)++;
    }
}

void calculate_index(int l, int w, int s) {
    if (w==0) {
        printf("Error: No words found.\n");
        return;
    }
    float L = ((float)l/w)*100;
    float S = ((float)s/w)*100;
    float index = 0.0588 * L - 0.296 * S - 15.8;

    int grade = roundf(index); // include math.h header
    if (grade<1) printf("Before Grade 1\n");
    else if (grade>=16) printf("Grade 16+\n");
    else printf("Grade %i\n", grade);
}

int main () {
    char text[1000];
    get_text(text); // get text as input
    int l=0, w=0, s=0; // letters, words, sentences
    parse_text(text, &l, &w, &s);   //parse text into letters, words and sentences
    calculate_index(l, w, s); // calculate coleman lieu index and print grade
    return 0;
}
