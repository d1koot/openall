# Shelf demo (our own programs only)

`notes.c` is the test target. `ref_empty.c` and `ref_stdio.c` are reference programs: same compiler, same flags,
different logic. `--learn` stores their function hashes (no binaries) in `refsets/` under the compiler's fingerprint,
so only the target's own code is left as `unknown`. `example_pages/` holds shelf 3 pages written for the build below.
Addresses in the pages belong to this exact toolchain and flags (GCC 13, msvcrt, -O1, stripped).

```bash
for p in notes ref_empty ref_stdio; do
  x86_64-w64-mingw32-gcc -O1 -o $p.exe $p.c && x86_64-w64-mingw32-strip -s $p.exe
done
pip install capstone pefile
python3 ../../scripts/build_shelves.py --learn ref_empty.exe ref_stdio.exe
S=../../workspace/shelves/notes
python3 ../../scripts/build_shelves.py notes.exe --out $S
python3 ../../scripts/shelf3.py stubs --shelves $S
mkdir -p $S/shelf3 && cp example_pages/*.md $S/shelf3/
python3 ../../scripts/shelf3.py check --shelves $S
python3 ../../scripts/shelf3.py book  --shelves $S
```
Expected: 2 functions `unknown` (`main`, `read_words`), `CHECK OK`, a book in `$S/book/`. Do not commit the .exe files.
