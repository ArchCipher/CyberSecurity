#include <ctype.h>
#include <stdio.h>

void get_input (char *word, int player) {
    do {
        printf("Player %i: ", player);
        scanf("%99s", word);
    } while(word[0]=='\0');
}

void to_uppercase (char *word) {
    int i=0;
    while (word[i]) {
        word[i] = toupper(word[i]);
        i++;
    }
}

int scores(char *word) {
    int score = 0;

    char point1[10] = {'A', 'E', 'I', 'L', 'N', 'O', 'R', 'S', 'T', 'U'};
    char point2[2] = {'D', 'G'};
    char point3[4] = {'B', 'C', 'M', 'P'};
    char point4[5] = {'F', 'H', 'V', 'W', 'Y'};
    char point5[1] = {'K'};
    char point8[2] = {'J', 'X'};
    char point10[2] = {'Q', 'Z'};

    int len1 = sizeof(point1) / sizeof(point1[0]);
    int len2 = sizeof(point2) / sizeof(point2[0]);
    int len3 = sizeof(point3) / sizeof(point3[0]);
    int len4 = sizeof(point4) / sizeof(point4[0]);
    int len5 = sizeof(point5) / sizeof(point5[0]);
    int len8 = sizeof(point8) / sizeof(point8[0]);
    int len10 = sizeof(point10) / sizeof(point10[0]);

    //iterate through words
    int i = 0;
    while (word[i]) {
        int matched = 0;
        for (int j=0; j<len1; j++) {
            if (word[i]==point1[j]) {score+=1; matched = 1; break;}
        }
        if (!matched)
        for (int j=0; j<len2; j++) {
            if (word[i]==point2[j]) {score+=2; matched = 1; break;}
        }
        if (!matched)
        for (int j=0; j<len3; j++) {
            if (word[i]==point3[j]) {score+=3; matched = 1; break;}
        }
        if (!matched)
        for (int j=0; j<len4; j++) {
            if (word[i]==point4[j]) { score+=4; matched = 1; break; }
        }
        if (!matched)
        for (int j=0; j<len5; j++) {
            if (word[i]==point5[j]) { score+=5; matched = 1; break; }
        }
        if (!matched)
        for (int j=0; j<len8; j++) {
            if (word[i]==point8[j]) { score+=8; matched = 1; break; }
        }
        if (!matched)
        for (int j=0; j<len10; j++) {
            if (word[i]==point10[j]) { score+=10; matched = 1; break; }
        }
            i++;
    }
    return score;
}

void print_result(int score1, int score2) {
if (score1 == score2) printf("Tie!\n");
else if (score1 > score2) printf("Player 1 wins!\n");
else printf("Player 2 wins!\n");
}

int main () {
char word1[100], word2[100];
get_input(word1, 1); //get input from player 1
get_input(word2, 2); //get input from player 2
to_uppercase(word1); // convert word 1 to uppercase
to_uppercase(word2); // convert word 2 to uppercase
int score1 = scores(word1); //calculate player 1's score
int score2 = scores(word2); //calculate player 2's score
char result[20];
print_result(score1, score2); //calculate and print result
return 0;
}
