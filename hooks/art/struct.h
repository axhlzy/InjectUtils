//
// Created by pc on 2023/8/22.
//

#ifndef IL2CPPHOOKER_STRUCT_H
#define IL2CPPHOOKER_STRUCT_H

#include <atomic>
#include <cstdint>

class ArtMethod {
public:
    void *declaring_class_; // GcRoot<mirror::Class> declaring_class_;
    std::atomic<std::uint32_t> access_flags_;
    // 方法 code 在 dex 中的偏移
    uint32_t dex_code_item_offset_;
    // 方法在 dex 中的 index
    uint32_t dex_method_index_;
    // 方法 index，对于虚方法，指的是 vtable 中的 index，对于接口方法，指的是 ifTable 中的 index
    uint16_t method_index_;
    // 方法的热度计数，Jit 会根据此变量决定是否将方法进行编译
    uint16_t hotness_count_;
    struct PtrSizedFields {
        void *data_;
        // 方法的入口
        void *entry_point_from_quick_compiled_code_;
    } ptr_sized_fields_;
};

struct LockCountData {
    void *monitors_; // std::unique_ptr<std::vector<mirror::Object*>> monitors_;
};

struct ShadowFrame {
    ShadowFrame *link_;
    ArtMethod *method_;
    void *result_register_; // JValue* result_register_;
    const uint16_t *dex_pc_ptr_;
    const uint16_t *dex_instructions_;
    LockCountData lock_count_data_; // This may contain GC roots when lock counting is active.
    const uint32_t number_of_vregs_;
    uint32_t dex_pc_;
    int16_t cached_hotness_countdown_;
    int16_t hotness_countdown_;
};

struct SwitchImplContext {
    void *self;           // Thread* self;
    void *const accessor; // const CodeItemDataAccessor& accessor;
    ShadowFrame &shadow_frame;
    void *result_register; // JValue& result_register;
    bool interpret_one_instruction;
    void *result; // JValue result;
};

#endif // IL2CPPHOOKER_STRUCT_H
