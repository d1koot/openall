# Overview of notes.exe (private book)

- The program reads a text file named on the command line and counts how often each word occurs, ignoring letter case. [I] refs: F:000015e0, F:00001506, I:msvcrt.dll!tolower
- It prints the total number of words, then one line per distinct word with its count and a numeric hash of the word. [I] refs: F:000015e0, S:00010022, S:00010033
- Without an argument it prints a usage message and exits with a failure code. [O] refs: S:00010006
- All of the program's own logic sits in two functions; 163 other functions were matched as compiler runtime or thin library thunks and were not analysed. [O] refs: F:000015e0, F:00001506
- Which exact C library functions the unanalysed runtime functions are (printf and scanf families) is a guess from how they are called. [G]
