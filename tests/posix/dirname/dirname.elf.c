#include <libgen.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>


int main() {
    int *good = (int *)(size_t)0xdead; 
    char buf[32];
    char *expected = NULL;
    char *actual = NULL;
    
    strcpy(buf, "/usr/local/lib");
    expected = "/usr/local";
    actual = dirname(buf);
    if(strcmp(actual, expected)) {
        printf("Expected %s, got %s\n", expected, actual);
        exit(1);
    }
    
    strcpy(buf, "/usr/lib/");
    expected = "/usr";
    actual = dirname(buf);
    if(strcmp(actual, expected)) {
        printf("Expected %s, got %s\n", expected, actual);
        exit(1);
    }
    
    strcpy(buf, "/usr/lib");
    expected = "/usr";
    actual = dirname(buf);
    if(strcmp(actual, expected)) {
        printf("Expected %s, got %s\n", expected, actual);
        exit(1);
    }
    
    strcpy(buf, "usr/lib");
    expected = "usr";
    actual = dirname(buf);
    if(strcmp(actual, expected)) {
        printf("Expected %s, got %s\n", expected, actual);
        exit(1);
    }

    strcpy(buf, "/usr");
    expected = "/";
    actual = dirname(buf);
    if(strcmp(actual, expected)) {
        printf("Expected %s, got %s\n", expected, actual);
        exit(1);
    }
    
    strcpy(buf, "usr");
    expected = ".";
    actual = dirname(buf);
    if(strcmp(actual, expected)) {
        printf("Expected %s, got %s\n", expected, actual);
        exit(1);
    }

    strcpy(buf, "/");
    expected = "/";
    actual = dirname(buf);
    if(strcmp(actual, expected)) {
        printf("Expected %s, got %s\n", expected, actual);
        exit(1);
    }
    
    strcpy(buf, ".");
    expected = ".";
    actual = dirname(buf);
    if(strcmp(actual, expected)) {
        printf("Expected %s, got %s\n", expected, actual);
        exit(1);
    }
    
    strcpy(buf, "..");
    expected = ".";
    actual = dirname(buf);
    if(strcmp(actual, expected)) {
        printf("Expected %s, got %s\n", expected, actual);
        exit(1);
    }

    return *good;

}
