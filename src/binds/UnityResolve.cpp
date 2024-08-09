#include "bindings.h"

void reg_UnityResolve(lua_State *L) {
    luabridge::getGlobalNamespace(L)
        .beginClass<UnityResolve>("UnityResolve")
        // .addStaticFunction("Init", &UnityResolve::Init)
        .addStaticFunction("Get", &UnityResolve::Get)
        .addStaticFunction("ThreadAttach", &UnityResolve::ThreadAttach)
        .addStaticFunction("ThreadDetach", &UnityResolve::ThreadDetach)
        // .addStaticFunction("DumpToFile", &UnityResolve::DumpToFile)

        .endClass()
        .deriveClass<UnityResolve::Assembly, UnityResolve>("Assembly")
        .addProperty("name", &UnityResolve::Assembly::name)
        // .addProperty("address", &UnityResolve::Assembly::address)
        .addProperty("file", &UnityResolve::Assembly::file)
        .addProperty("classes", &UnityResolve::Assembly::classes)
        .endClass()

        .deriveClass<UnityResolve::Type, UnityResolve>("Type")
        // .addProperty("address", &UnityResolve::Type::address)
        .addProperty("name", &UnityResolve::Type::name)
        .addProperty("size", &UnityResolve::Type::size)
        .endClass()

        .deriveClass<UnityResolve::Class, UnityResolve::Type>("Class")
        // .addProperty("classinfo", &UnityResolve::Class::classinfo)
        .addProperty("name", &UnityResolve::Class::name)
        .addProperty("parent", &UnityResolve::Class::parent)
        .addProperty("namespaze", &UnityResolve::Class::namespaze)
        .addProperty("fields", &UnityResolve::Class::fields)
        .addProperty("methods", &UnityResolve::Class::methods)
        .addFunction("Get", &UnityResolve::Class::Get<UnityResolve::Field>)
        .addFunction("GetField", &UnityResolve::Class::Get<UnityResolve::Field>)
        .addFunction("GetMethod", &UnityResolve::Class::Get<UnityResolve::Method>)
        // .addFunction("GetValue", &UnityResolve::Class::GetValue<std::int32_t>)
        // .addFunction("SetValue", &UnityResolve::Class::SetValue<std::int32_t>)
        // .addFunction("FindObjectsByType", &UnityResolve::Class::FindObjectsByType)
        // .addFunction("New", &UnityResolve::Class::New)
        // .endClass()

        // .deriveClass<UnityResolve::Field, UnityResolve::Field>("Field")
        // // .addProperty("fieldinfo", &UnityResolve::Field::fieldinfo)
        // .addProperty("name", &UnityResolve::Field::name)
        // .addProperty("type", &UnityResolve::Field::type)
        // .addProperty("klass", &UnityResolve::Field::klass)
        // .addProperty("offset", &UnityResolve::Field::offset)
        // .addProperty("static_field", &UnityResolve::Field::static_field)
        // // .addProperty("vTable", &UnityResolve::Field::vTable)
        // // .addFunction("GetValue", &UnityResolve::Field::GetValue<std::int32_t>)
        // // .addFunction("SetValue", &UnityResolve::Field::SetValue<std::int32_t>)
        // .endClass()

        // .deriveClass<UnityResolve::Method, UnityResolve::Method>("Method")
        // // .addProperty("address", &UnityResolve::Method::address)
        // .addProperty("name", &UnityResolve::Method::name)
        // .addProperty("klass", &UnityResolve::Method::klass)
        // .addProperty("return_type", &UnityResolve::Method::return_type)
        // .addProperty("flags", &UnityResolve::Method::flags)
        // .addProperty("static_function", &UnityResolve::Method::static_function)
        // // .addProperty("function", &UnityResolve::Method::function)
        // .addProperty("args", &UnityResolve::Method::args)
        // // .addFunction("Invoke", &UnityResolve::Method::Invoke<std::int32_t>)
        // // .addFunction("Compile", &UnityResolve::Method::Compile)
        // // .addFunction("RuntimeInvoke", &UnityResolve::Method::RuntimeInvoke<std::int32_t>)
        // // .addFunction("Cast", &UnityResolve::Method::Cast<std::int32_t>)
        .endClass();

    static auto unity = new UnityResolve();
    luabridge::setGlobal(L, unity, "UR");
    console->info("[*] luabridge bind {}", "UnityResolve");
}
