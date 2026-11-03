// Reference program: same toolchain, same STL pieces, different logic.
#include <algorithm>
#include <iostream>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
struct Animal {
    virtual ~Animal() = default;
    virtual std::string sound() const = 0;
    virtual int legs() const = 0;
};
struct Dog : Animal {
    std::string sound() const override { return "woof"; }
    int legs() const override { return 4; }
};
struct Bird : Animal {
    std::string sound() const override { return "tweet"; }
    int legs() const override { return 2; }
};
int main(int argc, char**) {
    std::vector<std::unique_ptr<Animal>> v;
    v.push_back(std::make_unique<Dog>());
    v.push_back(std::make_unique<Bird>());
    std::map<std::string, int> m;
    for (auto& a : v) m[a->sound()] += a->legs();
    std::sort(v.begin(), v.end(), [](const auto& x, const auto& y) { return x->legs() < y->legs(); });
    try {
        if (argc > 5) throw std::runtime_error("too many");
        for (auto& kv : m) std::cout << kv.first << " " << kv.second << "\n";
    } catch (const std::exception& e) {
        std::cerr << e.what() << "\n";
        return 1;
    }
    return 0;
}
