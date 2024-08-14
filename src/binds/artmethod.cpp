#include "android/art/runtime/art_method.h"
#include "bindings.h"

void showArtMethod(art::ArtMethod *artMethod) {
    console->info("declaring_class_: {:p}", (void *)(artMethod->declaring_class_.AddressWithoutBarrier()));
    console->info("access_flags_: {:p}", artMethod->access_flags_);
    // console->info("dex_code_item_offset_: {:p}", (void *)artMethod->dex_code_item_offset_);
    console->info("dex_method_index_: {:p}", artMethod->dex_method_index_);
    console->info("method_index_: {:p}", artMethod->method_index_);
    console->info("hotness_count_: {:p}", artMethod->hotness_count_);
    // ...
}

BINDFUNC(artmethod) {

    luabridge::getGlobalNamespace(L)
        .beginNamespace("artmethod")
        .addFunction("show", [](PTR artMethod) { showArtMethod(reinterpret_cast<art::ArtMethod *>(artMethod)); })
        .endNamespace();
}