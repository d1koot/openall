#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
int main(int argc, char **argv) {
    char line[128]; char *copy; int n = 0;
    if (argc > 1) { FILE *f = fopen(argv[1], "r"); if (!f) { perror("x"); return 1; }
        while (fscanf(f, "%127s", line) == 1) { if (strcmp(line, "end") == 0) break; n += toupper((unsigned char)line[0]); }
        fclose(f); }
    copy = _strdup("sample"); printf("%s %d\n", copy, n); fprintf(stderr, "done\n"); free(copy);
    return 0;
}
