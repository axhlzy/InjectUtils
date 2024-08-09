#ifndef IL2CPPHOOKER_LAMBDATRAM_HPP
#define IL2CPPHOOKER_LAMBDATRAM_HPP

/**
 * Description:
 * This class is used to register lambda function and convert it to a function pointer.
 * resolve the problem that Dobby can only pass function pointer as callback,
 * but not lambda expression with captured parameters
 */

#include <iostream>
#include <unordered_map>
#include <functional>
#include <mutex>
#include <type_traits>

using namespace std;

#define T int

template<T N>
struct Counter {
    static const T value = N;
};

template<T ID, typename Func>
struct FunctionWrapper;

template<T ID, typename Ret, typename ...Args>
struct FunctionWrapper<ID, std::function<Ret(Args...)>> {
    static std::function<Ret(Args...)> func;

    static Ret Trampoline(Args... args) {
        return func(args...);
    }
};

template<T ID, typename Ret, typename ...Args>
std::function<Ret(Args...)> FunctionWrapper<ID, std::function<Ret(Args...)>>::func;

class LambdaTram {
public:
    template<T ID, typename Ret, typename ...Args>
    static void* RegisterAndConvert(std::function<Ret(Args...)> func) {
        FunctionWrapper<ID, std::function<Ret(Args...)>>::func = func;
        return reinterpret_cast<void*>(&FunctionWrapper<ID, std::function<Ret(Args...)>>::Trampoline);
    }

    template<T ID, typename Callable>
    static void* RegisterAndConvert(Callable&& callable) {
        return RegisterAndConvert<ID>(std::function(callable));
    }

    template<T ID, typename Ret, typename ...Args>
    static Ret Execute(Args... args) {
        return FunctionWrapper<ID, std::function<Ret(Args...)>>::Trampoline(args...);
    }
};

template<typename Lambda>
auto make_function_impl(Lambda&& lambda) {
    return std::function{std::forward<Lambda>(lambda)};
}

template<typename Lambda>
auto make_function(Lambda&& lambda) -> decltype(make_function_impl(std::function{std::forward<Lambda>(lambda)})) {
    return make_function_impl(std::function{std::forward<Lambda>(lambda)});
}

#define MAKE_FUNCTION(func) make_function(func)
#define REGISTER_LAMBDA(func) LambdaTram::RegisterAndConvert<Counter<__COUNTER__>::value>(func)
#define REGISTER_LAMBDA_ID(ID, func) LambdaTram::RegisterAndConvert<ID>(func)

#undef T

#endif //IL2CPPHOOKER_LAMBDATRAM_HPP
