#include "bindings.h"

#ifdef __aarch64__
#define LINKERNAME "linker64"
#elif defined(__arm__)
#define LINKERNAME "linker"
#endif

static void *addr_getSoName = NULL;
static void *addr_get_somain = NULL;

#include "linker_soinfo.h"
using fn_get_soname = const char *(*)(soinfo *);
using fn_get_somain = soinfo *(*)(void);

void init() {
    void *handle = xdl_open(LINKERNAME, XDL_DEFAULT);
    if (handle == nullptr)
        throw std::runtime_error("Open linker failed");

    // get somain
    addr_getSoName = xdl_dsym(handle, "__dl__ZNK6soinfo10get_sonameEv", NULL);
    using fn_get_soname = const char *(*)(soinfo *);
    if (addr_getSoName == nullptr)
        throw std::runtime_error("linker : get_soname failed");

    // get soname
    addr_get_somain = xdl_dsym(handle, "__dl__Z17solist_get_somainv", NULL);
    using fn_get_somain = soinfo *(*)(void);
    if (addr_get_somain == nullptr)
        throw std::runtime_error("linker : get_somain failed");

    xdl_close(handle);
}

// __dl__Z17solist_get_somainv
PTR get_somain() {
    using fn = PTR (*)(void);
    auto ret = reinterpret_cast<fn>(addr_get_somain)();
    console->warn("got [ soinfo* main ] -> {}", (void *)ret);
    return ret;
}

// (soinfo) {
//   phdr = 0x0000007ce3322040
//   phnum = 10
//   base = 536387657728
//   size = 73728
//   dynamic = 0x0000007ce3331e38
//   next = 0x0000007ce5a57eb0
//   flags_ = 1073743169
//   strtab_ = 0x0000007ce3323f94 ""
//   symtab_ = 0x0000007ce33222a8
//   nbucket_ = 0
//   nchain_ = 0
//   bucket_ = 0x0000000000000000
//   chain_ = 0x0000000000000000
//   plt_rela_ = 0x0000007ce3325308
//   plt_rela_count_ = 141
//   rela_ = nullptr
//   rela_count_ = 0
//   preinit_array_ = 0x0000000000000000
//   preinit_array_count_ = 0
//   init_array_ = 0x0000000000000000
//   init_array_count_ = 0
//   fini_array_ = 0x0000007ce3331e28
//   fini_array_count_ = 2
//   init_func_ = 0x0000000000000000
//   fini_func_ = 0x0000000000000000
//   ref_count_ = 0
//   link_map_head = {
//     l_addr = 536387657728
//     l_name = 0x0000007ce5abb840 "/system/lib64/libcutils.so"
//     l_ld = 0x0000007ce3331e38
//     l_next = 0x0000007ce5a57f80
//     l_prev = 0x0000007ce5a57aa0
//   }
//   constructors_called = true
//   load_bias = 536387657728
//   has_DT_SYMBOLIC = false
//   version_ = 6
//   st_dev_ = 64773
//   st_ino_ = 2085
//   children_ = {
//     head_ = 0x0000007ce5b3d660
//     tail_ = 0x0000007ce5b3d700
//   }
//   parents_ = {
//     head_ = 0x0000007ce5b3c4f0
//     tail_ = 0x0000007ce5b51460
//   }
//   file_offset_ = 0
//   rtld_flags_ = 256
//   dt_flags_1_ = 1
//   strtab_size_ = 4777
//   gnu_nbucket_ = 29
//   gnu_bucket_ = 0x0000007ce3323d48
//   gnu_chain_ = 0x0000007ce3323bbc
//   gnu_maskwords_ = 31
//   gnu_shift2_ = 26
//   gnu_bloom_filter_ = 0x0000007ce3323c48
//   local_group_root_ = 0x0000007ce5a57010
//   android_relocs_ = 0x0000007ce3325240 "APS2\f"
//   android_relocs_size_ = 107
//   soname_ = "libcutils.so"
//   realpath_ = "/system/lib64/libcutils.so"
//   versym_ = 0x0000007ce33239b8
//   verdef_ptr_ = 0
//   verdef_cnt_ = 0
//   verneed_ptr_ = 536387664804
//   verneed_cnt_ = 3
//   target_sdk_version_ = 0
//   dt_runpath_ = size=0 {}
//   primary_namespace_ = 0x0000007ce6cd64e0
//   secondary_namespaces_ = (head_ = 0x0000007ce5934370, tail_ = 0x0000007ce5936070)
//   handle_ = 9789523434609700899
//   relr_ = 0x0000007ce33252b0
//   relr_count_ = 11
//   tls_ = nullptr {
//     pointer = nullptr
//   }
//   tlsdesc_args_ = size=0 {}
//   gap_start_ = 536387842048
//   gap_size_ = 0
// }

void disp_soinfo_link() {

    void *handle = xdl_open(LINKERNAME, XDL_DEFAULT);

    auto info = reinterpret_cast<fn_get_somain>(addr_get_somain)();
    auto next = info->next;
    int index = 0;

    do {
        auto soname = reinterpret_cast<fn_get_soname>(addr_getSoName)(info);
        auto phnum = info->phnum;
        auto phdr = info->phdr;
        auto base = info->base;
        auto size = info->size;
        auto dynamic = info->dynamic;
        console->info("{} {} <- {} \n\tphdr : {} phnum : {} \n\tbase : {} | size : {} | dynamic : {}",
                      index++, (void *)info, soname, (void *)phdr, phnum, (void *)base, size, (void *)dynamic);
        info = info->next;
    } while (info != NULL);

    xdl_close(handle);
}

void disp_link_map_head() {
    auto info = reinterpret_cast<fn_get_somain>(addr_get_somain)();
    auto next = info->next;

    auto soname = reinterpret_cast<fn_get_soname>(addr_getSoName)(info);
    auto link_current = info->link_map_head;
    auto load_bias = info->load_bias;
    console->info("{} {} | link_map_head : {} | load_bias : {}", (void *)info, soname, (void *)&link, load_bias);

    struct link_map *l_next = &link_current;

    do {
        console->info("l_addr: 0x{:X}, l_name: {} \n\tl_ld: {}, l_next: {}, l_prev: {} }}",
                      l_next->l_addr,
                      l_next->l_name ? l_next->l_name : "null",
                      static_cast<void *>(l_next->l_ld),
                      static_cast<void *>(l_next->l_next),
                      static_cast<void *>(l_next->l_prev));
        l_next = l_next->l_next;
    } while (l_next != NULL);
}

BINDFUNC(linker) {
    init();
    luabridge::getGlobalNamespace(L)
        .beginNamespace("linker")
        .addFunction("somain", get_somain)
        .addFunction("disp_soinfo_link", disp_soinfo_link)
        .addFunction("disp_link_map_head", disp_link_map_head)
        .endNamespace();
}