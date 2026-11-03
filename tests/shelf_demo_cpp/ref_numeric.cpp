// Reference program: number parsing and formatting through the usual library routes
// (stod, strtod, atof, cout << double, to_string, snprintf, sscanf, string streams).
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>
int main(int argc, char** argv) {
    double x = argc > 1 ? std::stod(argv[1]) : 1.5;
    double y = argc > 2 ? std::strtod(argv[2], nullptr) : 2.25;
    double z = argc > 3 ? std::atof(argv[3]) : 0.125;
    std::cout << x << " " << y << " " << z << "\n";
    std::cout << std::to_string(x * y) << "\n";
    char buf[64];
    std::snprintf(buf, sizeof buf, "%g %f %.3e", x, y, z);
    std::printf("%s\n", buf);
    std::ostringstream os;
    os << x + y + z;
    std::cerr << os.str() << "\n";
    double w = 0;
    std::sscanf(buf, "%lf", &w);
    std::istringstream is("3.5 4.5");
    double a = 0, b = 0;
    is >> a >> b;
    return (int)(w + a + b) > 100 ? 1 : 0;
}
