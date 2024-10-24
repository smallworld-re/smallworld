#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

char string1[] = "$Space is big. You just won't believe how vastly, hugely, mind-bogglingly big it is. I mean, you may think it's a long way down the road to the chemist's, but that's just peanuts to space.$";

char string2[] = "$A towel, [The Hitchhiker's Guide to the Galaxy] says, is about the most massively useful thing an interstellar hitchhiker can have. Partly it has great practical value. You can wrap it around you for warmth as you bound across the cold moons of Jaglan Beta; you can lie on it on the brilliant marble-sanded beaches of Santraginus V, inhaling the heady sea vapors; you can sleep under it beneath the stars which shine so redly on the desert world of Kakrafoon; use it to sail a miniraft down the slow heavy River Moth; wet it for use in hand-to-hand-combat; wrap it round your head to ward off noxious fumes or avoid the gaze of the Ravenous Bugblatter Beast of Traal (such a mind-boggingly stupid animal, it assumes that if you can't see it, it can't see you); you can wave your towel in emergencies as a distress signal, and of course dry yourself off with it if it still seems to be clean enough.$";



int deobfus_str(char *s) {
    char *orig_s = s;
    char key = *s;
    s ++;
    while (1) {
        char v = *s ^ key;
        if (!v) break;
        *s = v;
        s ++;
    }
    return s-orig_s+1;
}


void deobfus_strs() {
    deobfus_str(string1);
    deobfus_str(string2);   
}    


void prs(char *label,  char *s) {
    printf("%s: [", label);
    do {
        if (isprint(*s))
            printf("%c", *s);
        else 
            printf(".");
        s += 1;
    } while (*s);
    printf("]\n");
}


int main (int argc, char **argv) {

    deobfus_strs();

    prs("string1", 1+string1);
    prs("string2", 1+string2);

#if DEOBFS
#else

    int l1 = strlen(string1);
    int l2 = strlen(string2);
    FILE *fp = fopen("new_strings", "w");
    fwrite(&l1, sizeof(l1), 1, fp);
    fwrite(string1, l1, 1, fp);
    fwrite(&l2, sizeof(l2), 1, fp);
    fwrite(string2, l2, 1, fp);
    fclose(fp);

#endif

}    
