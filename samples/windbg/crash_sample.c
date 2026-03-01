/*
 * crash_sample.c - Minimal program that crashes with a null pointer dereference.
 * Used for WinDbg/CDB testing with ChatDBG.
 *
 * Compile: cl /Zi /Od crash_sample.c
 *    Or:   gcc -g -O0 -o crash_sample.exe crash_sample.c
 */

#include <stdio.h>
#include <stdlib.h>

int process_data(int *ptr) {
    /* Dereference a NULL pointer -- triggers access violation (0xC0000005) */
    return *ptr + 1;
}

int main(int argc, char **argv) {
    int *ptr = NULL;
    printf("About to crash...\n");
    int result = process_data(ptr);
    printf("Result: %d\n", result);
    return 0;
}
