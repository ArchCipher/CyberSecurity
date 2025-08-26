#include <strlen.h>

int ft_strlen (char *s) {
    int n=0;
    while (*s != '\0') {
        n++;
        s++; // s = s+1
    }
    return n;
}
