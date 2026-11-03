/* Test program written for OpenAll prototype. Own code, own exe. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

typedef struct Node { char *word; int count; struct Node *next; } Node;

static unsigned hash_word(const char *s) {
    unsigned h = 5381;
    while (*s) h = h * 33u + (unsigned char)*s++;
    return h;
}

static Node *find_or_add(Node **head, const char *w) {
    for (Node *n = *head; n; n = n->next)
        if (strcmp(n->word, w) == 0) return n;
    Node *n = malloc(sizeof *n);
    n->word = _strdup(w); n->count = 0; n->next = *head; *head = n;
    return n;
}

static void normalize(char *s) {
    for (; *s; s++) *s = (char)tolower((unsigned char)*s);
}

static int read_words(FILE *f, Node **head) {
    char buf[256]; int total = 0;
    while (fscanf(f, "%255s", buf) == 1) {
        normalize(buf);
        find_or_add(head, buf)->count++;
        total++;
    }
    return total;
}

static void print_report(Node *head, int total) {
    printf("Total words: %d\n", total);
    for (Node *n = head; n; n = n->next)
        printf("%-20s %5d  (hash %08x)\n", n->word, n->count, hash_word(n->word));
}

static void free_all(Node *n) {
    while (n) { Node *x = n->next; free(n->word); free(n); n = x; }
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "Usage: notes <file>\n"); return 2; }
    FILE *f = fopen(argv[1], "r");
    if (!f) { perror("open"); return 1; }
    Node *head = NULL;
    int total = read_words(f, &head);
    fclose(f);
    print_report(head, total);
    free_all(head);
    return 0;
}
