#ifndef IL2CPPHOOKER_LAMBDATRAM_HPP
#define IL2CPPHOOKER_LAMBDATRAM_HPP

/**
 * @file LambdaTram.hpp
 * @brief Lambda 函数转换工具
 * 
 * 该类用于将 Lambda 表达式（包括捕获参数的 Lambda）转换为函数指针。
 * 解决了 Dobby 等 Hook 框架只能接受函数指针作为回调，
 * 而不能直接使用带捕获参数的 Lambda 表达式的问题。
 * 
 * @note 使用编译时计数器 __COUNTER__ 为每个 Lambda 生成唯一 ID
 */

#include <functional>
#include <type_traits>

// 使用 int 作为计数器类型
using CounterType = int;

/**
 * @brief 编译时计数器
 * @tparam N 计数器值
 */
template<CounterType N>
struct Counter {
    static constexpr CounterType value = N;
};

/**
 * @brief 函数包装器前向声明
 */
template<CounterType ID, typename Func>
struct FunctionWrapper;

/**
 * @brief 函数包装器特化
 * 
 * 为每个唯一的 ID 和函数签名创建一个静态存储和跳板函数
 */
template<CounterType ID, typename Ret, typename ...Args>
struct FunctionWrapper<ID, std::function<Ret(Args...)>> {
    static std::function<Ret(Args...)> func;

    static Ret Trampoline(Args... args) {
        return func(args...);
    }
};

template<CounterType ID, typename Ret, typename ...Args>
std::function<Ret(Args...)> FunctionWrapper<ID, std::function<Ret(Args...)>>::func;

/**
 * @brief Lambda 跳板类
 * 
 * 提供将 Lambda 表达式注册并转换为函数指针的功能
 */
class LambdaTram {
public:
    /**
     * @brief 注册 std::function 并转换为函数指针
     * 
     * @tparam ID 唯一标识符
     * @tparam Ret 返回类型
     * @tparam Args 参数类型
     * @param func std::function 对象
     * @return void* 可调用的函数指针
     */
    template<CounterType ID, typename Ret, typename ...Args>
    static void* RegisterAndConvert(std::function<Ret(Args...)> func) {
        FunctionWrapper<ID, std::function<Ret(Args...)>>::func = func;
        return reinterpret_cast<void*>(&FunctionWrapper<ID, std::function<Ret(Args...)>>::Trampoline);
    }

    /**
     * @brief 注册可调用对象并转换为函数指针
     * 
     * @tparam ID 唯一标识符
     * @tparam Callable 可调用对象类型
     * @param callable 可调用对象（Lambda、函数对象等）
     * @return void* 可调用的函数指针
     */
    template<CounterType ID, typename Callable>
    static void* RegisterAndConvert(Callable&& callable) {
        return RegisterAndConvert<ID>(std::function(callable));
    }

    /**
     * @brief 执行已注册的函数
     * 
     * @tparam ID 唯一标识符
     * @tparam Ret 返回类型
     * @tparam Args 参数类型
     * @param args 函数参数
     * @return Ret 函数返回值
     */
    template<CounterType ID, typename Ret, typename ...Args>
    static Ret Execute(Args... args) {
        return FunctionWrapper<ID, std::function<Ret(Args...)>>::Trampoline(args...);
    }
};

/**
 * @brief 从 Lambda 创建 std::function（内部实现）
 */
template<typename Lambda>
auto make_function_impl(Lambda&& lambda) {
    return std::function{std::forward<Lambda>(lambda)};
}

/**
 * @brief 从 Lambda 创建 std::function
 */
template<typename Lambda>
auto make_function(Lambda&& lambda) -> decltype(make_function_impl(std::function{std::forward<Lambda>(lambda)})) {
    return make_function_impl(std::function{std::forward<Lambda>(lambda)});
}

/**
 * @def MAKE_FUNCTION(func)
 * @brief 将 Lambda 转换为 std::function
 */
#define MAKE_FUNCTION(func) make_function(func)

/**
 * @def REGISTER_LAMBDA(func)
 * @brief 注册 Lambda 并转换为函数指针（自动生成 ID）
 * 
 * 使用 __COUNTER__ 自动为每个调用生成唯一 ID
 */
#define REGISTER_LAMBDA(func) LambdaTram::RegisterAndConvert<Counter<__COUNTER__>::value>(func)

/**
 * @def REGISTER_LAMBDA_ID(ID, func)
 * @brief 注册 Lambda 并转换为函数指针（手动指定 ID）
 * 
 * @param ID 手动指定的唯一标识符
 * @param func Lambda 表达式或可调用对象
 */
#define REGISTER_LAMBDA_ID(ID, func) LambdaTram::RegisterAndConvert<ID>(func)

#endif // IL2CPPHOOKER_LAMBDATRAM_HPP
