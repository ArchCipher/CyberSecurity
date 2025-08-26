#include <stdio.h>

int get_input () {
    int n;
    do {
        printf("Enter a number between 1 and 8: ");
        scanf("%i", &n);
    } while (n<1 || n>8);

    return n;
}

void mario (int n) {
    for (int i=0; i<n; i++) {
        // print space
        for (int j=0; j<n-(i+1); j++) {
            printf(" ");
        }
        // print left #
        for (int j=0; j<i+1; j++) {
            printf("#");
        }
        printf("  "); // print double space
        //print right #
        for (int j=0; j<i+1; j++) {
            printf("#");
        }
        printf("\n"); // print newline
    }
}

int main() {
    int n = get_input();
    mario(n);
}
