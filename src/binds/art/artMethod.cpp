#include "android/art/runtime/art_method.h"
#include "bindings.h"

void showArtMethod(art::ArtMethod *artMethod) {

    // console->info("{}", artMethod->PrettyMethod());

    logd("declaring_class_: %p", (void *)(artMethod->declaring_class_.AddressWithoutBarrier()));
    // logd("access_flags_: %p", artMethod->access_flags_);
    // console->info("dex_code_item_offset_: {:p}", (void *)artMethod->dex_code_item_offset_);
    logd("dex_method_index_: %u", artMethod->dex_method_index_);
    logd("method_index_: %hu", artMethod->method_index_);
    logd("hotness_count_: %hu", artMethod->hotness_count_);


    console->info("declaring_class_: {:p}, dex_method_index_: {:p}, method_index_: {:p}, hotness_count_: {:p}", 
                  static_cast<void*>(artMethod->declaring_class_.AddressWithoutBarrier()),
                  artMethod->dex_method_index_,
                  artMethod->method_index_,
                  artMethod->hotness_count_);
    // ...
}

BINDFUNC(artmethod) {

    luabridge::getGlobalNamespace(L)
        .beginNamespace("artmethod")
        .addFunction("show", [](PTR artMethod) { showArtMethod(reinterpret_cast<art::ArtMethod *>(artMethod)); })
        .endNamespace();
}