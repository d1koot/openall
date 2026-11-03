# Reference programs for C++ (own programs only)

`ref_empty.cpp`, `ref_stl.cpp` and `ref_numeric.cpp` are small programs that teach the builder what the compiler's own and the
standard library's code looks like. Compile them with the SAME compiler and flags as the program you want to
study, then learn them. Only function hashes are stored (in `refsets/`), never binaries.

Easiest on Windows: double-click `setup_windows.bat` in the project folder. It checks Python and g++ (offering to
install them with winget, asking first), compiles these three programs into `out\` and learns them.

By hand (64-bit g++ or MSVC x64 prompt):
```
g++ -O2 -std=c++17 -o ref_empty.exe ref_empty.cpp
g++ -O2 -std=c++17 -o ref_stl.exe ref_stl.cpp
g++ -O2 -std=c++17 -o ref_numeric.exe ref_numeric.cpp
python scripts/build_shelves.py --learn ref_empty.exe ref_stl.exe ref_numeric.exe
```
A reference set is only valid for the compiler that made it AND for the analyser version that learned it; the
builder tells you when a set is stale.

Never put the source of the program under test into the project folder: the model could read it and the test
would no longer be blind.
