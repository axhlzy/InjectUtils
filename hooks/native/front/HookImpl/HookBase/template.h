//
// Created by lzy on 2023/9/13.
//

#ifndef IL2CPPHOOKER_TEMPLATE_H
#define IL2CPPHOOKER_TEMPLATE_H

template <typename>
struct function_traits;

template <typename Ret, typename... Params>
struct function_traits<Ret (*)(Params...)> {
    using return_type = Ret;
    using parameter_types = std::tuple<Params...>;
};

template <typename Ret, typename Class, typename... Params>
struct function_traits<Ret (Class::*)(Params...)> {
    using return_type = Ret;
    using parameter_types = std::tuple<Params...>;
};

template <typename Ret, typename Class, typename... Params>
struct function_traits<Ret (Class::*)(Params...) const> {
    using return_type = Ret;
    using parameter_types = std::tuple<Params...>;
};

template <typename T>
struct is_std_function : std::false_type {};

template <typename Ret, typename... Args>
struct is_std_function<std::function<Ret(Args...)>> : std::true_type {};

template <typename>
struct function_traits;

template <typename Ret, typename... Args>
struct function_traits<std::function<Ret(Args...)>> {
    using return_type = Ret;
    using parameter_types = std::tuple<Args...>;
};

template <typename... Args>
using FuncType = void *(*)(Args...);

template <typename... Args>
using FuncTypeNull = std::nullptr_t (*)(Args...);

template <typename... Args>
using FuncTypeNoRet = void (*)(Args...);

template <typename... Args>
using FuncTypeRetInt = int (*)(Args...);

template <typename... Args>
using FuncTypeRetBool = bool (*)(Args...);

#endif // IL2CPPHOOKER_TEMPLATE_H
