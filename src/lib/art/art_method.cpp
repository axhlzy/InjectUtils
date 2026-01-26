#include "art/art_method.h"
#include "log.h"
#include "xdl.h"
#include "dex/dex_file.h"

#include <dlfcn.h>
#include <cstring>

jvmtiEnv* GetGlobalJvmtiEnv();

namespace art {

// ========== 字段地址获取 ==========

uint32_t* ArtMethod::GetDeclaringClassPtr() {
    return reinterpret_cast<uint32_t*>(GetFieldAddress(0));
}

uint32_t* ArtMethod::GetAccessFlagsPtr() {
    return reinterpret_cast<uint32_t*>(GetFieldAddress(GcRootSize));
}

uint32_t* ArtMethod::GetDexCodeItemOffsetPtr() {
    return reinterpret_cast<uint32_t*>(GetFieldAddress(GcRootSize + 0x4));
}

uint32_t* ArtMethod::GetDexMethodIndexPtr() {
    return reinterpret_cast<uint32_t*>(GetFieldAddress(GcRootSize + 0x8));
}

uint16_t* ArtMethod::GetMethodIndexPtr() {
    return reinterpret_cast<uint16_t*>(GetFieldAddress(GcRootSize + 0xC));
}

uint16_t* ArtMethod::GetHotnessCountPtr() {
    return reinterpret_cast<uint16_t*>(GetFieldAddress(GcRootSize + 0xE));
}

uint16_t* ArtMethod::GetImtIndexPtr() {
    return GetHotnessCountPtr();  // Union with hotness_count
}

void** ArtMethod::GetDataPtr() {
    return reinterpret_cast<void**>(GetFieldAddress(GcRootSize + 0x10));
}

void** ArtMethod::GetEntryPointFromQuickCompiledCodePtr() {
    return reinterpret_cast<void**>(GetFieldAddress(GcRootSize + 0x10 + PointerSize));
}

// ========== Getter 方法 ==========

uint32_t ArtMethod::GetDeclaringClassRef() const {
    return *reinterpret_cast<const uint32_t*>(GetFieldAddress(0));
}

uint32_t ArtMethod::GetAccessFlags() const {
    return *reinterpret_cast<const uint32_t*>(GetFieldAddress(GcRootSize));
}

uint32_t ArtMethod::GetDexCodeItemOffset() const {
    return *reinterpret_cast<const uint32_t*>(GetFieldAddress(GcRootSize + 0x4));
}

uint32_t ArtMethod::GetDexMethodIndex() const {
    return *reinterpret_cast<const uint32_t*>(GetFieldAddress(GcRootSize + 0x8));
}

uint16_t ArtMethod::GetMethodIndex() const {
    return *reinterpret_cast<const uint16_t*>(GetFieldAddress(GcRootSize + 0xC));
}

uint16_t ArtMethod::GetHotnessCount() const {
    return *reinterpret_cast<const uint16_t*>(GetFieldAddress(GcRootSize + 0xE));
}

uint16_t ArtMethod::GetImtIndex() const {
    return GetHotnessCount();  // Union
}

void* ArtMethod::GetData() const {
    return *reinterpret_cast<void* const*>(GetFieldAddress(GcRootSize + 0x10));
}

void* ArtMethod::GetJniCode() const {
    return GetData();  // Alias for native methods
}

void* ArtMethod::GetEntryPointFromQuickCompiledCode() const {
    return *reinterpret_cast<void* const*>(GetFieldAddress(GcRootSize + 0x10 + PointerSize));
}

// ========== Setter 方法 ==========

void ArtMethod::SetAccessFlags(uint32_t flags) {
    *GetAccessFlagsPtr() = flags;
}

void ArtMethod::SetDexCodeItemOffset(uint32_t offset) {
    *GetDexCodeItemOffsetPtr() = offset;
}

void ArtMethod::SetDexMethodIndex(uint32_t index) {
    *GetDexMethodIndexPtr() = index;
}

void ArtMethod::SetMethodIndex(uint16_t index) {
    *GetMethodIndexPtr() = index;
}

void ArtMethod::SetHotnessCount(uint16_t count) {
    *GetHotnessCountPtr() = count;
}

void ArtMethod::SetData(void* data) {
    *GetDataPtr() = data;
}

void ArtMethod::SetEntryPointFromQuickCompiledCode(void* entry_point) {
    *GetEntryPointFromQuickCompiledCodePtr() = entry_point;
}

// ========== 访问标志检查 ==========

bool ArtMethod::IsPublic() const {
    return (GetAccessFlags() & AccessFlags::kAccPublic) != 0;
}

bool ArtMethod::IsPrivate() const {
    return (GetAccessFlags() & AccessFlags::kAccPrivate) != 0;
}

bool ArtMethod::IsProtected() const {
    return (GetAccessFlags() & AccessFlags::kAccProtected) != 0;
}

bool ArtMethod::IsStatic() const {
    return (GetAccessFlags() & AccessFlags::kAccStatic) != 0;
}

bool ArtMethod::IsFinal() const {
    return (GetAccessFlags() & AccessFlags::kAccFinal) != 0;
}

bool ArtMethod::IsSynchronized() const {
    return (GetAccessFlags() & AccessFlags::kAccSynchronized) != 0;
}

bool ArtMethod::IsBridge() const {
    return (GetAccessFlags() & AccessFlags::kAccBridge) != 0;
}

bool ArtMethod::IsVarargs() const {
    return (GetAccessFlags() & AccessFlags::kAccVarargs) != 0;
}

bool ArtMethod::IsNative() const {
    return (GetAccessFlags() & AccessFlags::kAccNative) != 0;
}

bool ArtMethod::IsAbstract() const {
    return (GetAccessFlags() & AccessFlags::kAccAbstract) != 0;
}

bool ArtMethod::IsStrict() const {
    return (GetAccessFlags() & AccessFlags::kAccStrict) != 0;
}

bool ArtMethod::IsSynthetic() const {
    return (GetAccessFlags() & AccessFlags::kAccSynthetic) != 0;
}

bool ArtMethod::IsConstructor() const {
    return (GetAccessFlags() & AccessFlags::kAccConstructor) != 0;
}

bool ArtMethod::IsDeclaredSynchronized() const {
    return (GetAccessFlags() & AccessFlags::kAccDeclaredSynchronized) != 0;
}

bool ArtMethod::IsObsolete() const {
    return (GetAccessFlags() & AccessFlags::kAccObsoleteMethod) != 0;
}

bool ArtMethod::IsIntrinsic() const {
    return (GetAccessFlags() & AccessFlags::kAccIntrinsic) != 0;
}

// ========== 实用方法 ==========

void* ArtMethod::GetCodeItem(void* dex_file_begin) const {
    uint32_t offset = GetDexCodeItemOffset();
    if (offset == 0) {
        return nullptr;
    }
    return reinterpret_cast<void*>(
        reinterpret_cast<uintptr_t>(dex_file_begin) + offset);
}

bool ArtMethod::HasCodeItem() const {
    return GetDexCodeItemOffset() != 0;
}

bool ArtMethod::IsJniMethod() const {
    return IsNative();
}

void ArtMethod::CopyFrom(const ArtMethod* src) {
    if (src == nullptr) return;
    
    // 复制所有字段（除了 declaring_class）
    SetAccessFlags(src->GetAccessFlags());
    SetDexCodeItemOffset(src->GetDexCodeItemOffset());
    SetDexMethodIndex(src->GetDexMethodIndex());
    SetMethodIndex(src->GetMethodIndex());
    SetHotnessCount(src->GetHotnessCount());
    SetData(src->GetData());
    SetEntryPointFromQuickCompiledCode(src->GetEntryPointFromQuickCompiledCode());
}

bool ArtMethod::IsSameMethod(const ArtMethod* other) const {
    if (other == nullptr) return false;
    
    // 简单比较：检查 dex_method_index 和 declaring_class
    return GetDexMethodIndex() == other->GetDexMethodIndex() &&
           GetDeclaringClassRef() == other->GetDeclaringClassRef();
}

const DexFile* ArtMethod::GetDexFile() const {
    // 通过 xdl 调用 ART 的 GetDexFile 方法
    // art::ArtMethod::GetDexFile() const
    // _ZNK3art9ArtMethod10GetDexFileEv
    void* handle = xdl_open("libart.so", XDL_DEFAULT);
    if (handle == nullptr) {
        return nullptr;
    }
    
    typedef const DexFile* (*GetDexFileFunc)(const ArtMethod*);
    auto func = reinterpret_cast<GetDexFileFunc>(
        xdl_sym(handle, "_ZNK3art9ArtMethod10GetDexFileEv", nullptr));
    
    if (func == nullptr) {
        xdl_close(handle);
        return nullptr;
    }
    
    const DexFile* result = func(this);
    xdl_close(handle);
    
    return result;
}

// ========== 方法信息（通过 JVMTI） ==========

std::string ArtMethod::GetMethodName() const {
    jvmtiEnv* jvmti = GetGlobalJvmtiEnv();
    if (jvmti == nullptr) {
        return "<unknown>";
    }
    
    jmethodID jmethod = reinterpret_cast<jmethodID>(const_cast<ArtMethod*>(this));
    char* method_name = nullptr;
    char* method_sig = nullptr;
    
    jvmtiError error = jvmti->GetMethodName(jmethod, &method_name, &method_sig, nullptr);
    if (error != JVMTI_ERROR_NONE) {
        return "<error>";
    }
    
    std::string result;
    if (method_name != nullptr) {
        result = method_name;
        jvmti->Deallocate(reinterpret_cast<unsigned char*>(method_name));
    }
    if (method_sig != nullptr) {
        result += method_sig;
        jvmti->Deallocate(reinterpret_cast<unsigned char*>(method_sig));
    }
    
    return result;
}

std::string ArtMethod::GetDeclaringClassName() const {
    jvmtiEnv* jvmti = GetGlobalJvmtiEnv();
    if (jvmti == nullptr) {
        return "<unknown>";
    }
    
    jmethodID jmethod = reinterpret_cast<jmethodID>(const_cast<ArtMethod*>(this));
    jclass declaring_class = nullptr;
    
    jvmtiError error = jvmti->GetMethodDeclaringClass(jmethod, &declaring_class);
    if (error != JVMTI_ERROR_NONE || declaring_class == nullptr) {
        return "<error>";
    }
    
    char* class_sig = nullptr;
    error = jvmti->GetClassSignature(declaring_class, &class_sig, nullptr);
    if (error != JVMTI_ERROR_NONE || class_sig == nullptr) {
        return "<error>";
    }
    
    std::string result = class_sig;
    jvmti->Deallocate(reinterpret_cast<unsigned char*>(class_sig));
    
    return result;
}

std::string ArtMethod::GetPrettyMethod(bool with_signature) const {
    std::string class_name = GetDeclaringClassName();
    std::string method_name = GetMethodName();
    
    if (!with_signature) {
        // 只返回类名.方法名
        size_t sig_pos = method_name.find('(');
        if (sig_pos != std::string::npos) {
            method_name = method_name.substr(0, sig_pos);
        }
    }
    
    return class_name + " " + method_name;
}

std::string ArtMethod::GetAccessFlagsString() const {
    std::string result;
    uint32_t flags = GetAccessFlags();
    
    if (IsPublic()) result += "public ";
    if (IsPrivate()) result += "private ";
    if (IsProtected()) result += "protected ";
    if (IsStatic()) result += "static ";
    if (IsFinal()) result += "final ";
    if (IsSynchronized()) result += "synchronized ";
    if (IsNative()) result += "native ";
    if (IsAbstract()) result += "abstract ";
    if (IsSynthetic()) result += "synthetic ";
    if (IsConstructor()) result += "constructor ";
    if (IsObsolete()) result += "obsolete ";
    if (IsIntrinsic()) result += "intrinsic ";
    
    // 移除末尾空格
    if (!result.empty() && result.back() == ' ') {
        result.pop_back();
    }
    
    return result;
}

// ========== 调试方法 ==========

void ArtMethod::Print() const {
    loge("[*] ArtMethod @ %p", this);
    loge("[*]   declaring_class_ref: 0x%08x", GetDeclaringClassRef());
    loge("[*]   access_flags: 0x%08x (%s)", GetAccessFlags(), GetAccessFlagsString().c_str());
    loge("[*]   CodeItemOffset: 0x%08x", GetDexCodeItemOffset());
    logd("[*]   DexMethodIndex: %u, MethodIndex: %u", GetDexMethodIndex(), GetMethodIndex());
    loge("[*]   hotness_count: %u", GetHotnessCount());
    loge("[*]   data: %p", GetData());
    loge("[*]   entry_point: %p", GetEntryPointFromQuickCompiledCode());
    loge("[*]   method: %s", GetPrettyMethod(true).c_str());
    logd("[*]   IsNative: %s, IsAbstract: %s", IsNative() ? "yes" : "no", IsAbstract() ? "yes" : "no");
}

// std::string PrettyMethod(bool with_signature)
// _ZN3art9ArtMethod12PrettyMethodEb
std::string ArtMethod::PrettyMethodNative(bool with_signature) const {
    void* handle = xdl_open("libart.so", XDL_DEFAULT);
    if (handle == nullptr) {
        logw("[!] Failed to open libart.so");
        return GetPrettyMethod(with_signature);
    }
    
    typedef void (*PrettyMethodFunc)(const ArtMethod*, std::string*, bool);
    auto func = reinterpret_cast<PrettyMethodFunc>(
        xdl_sym(handle, "_ZN3art9ArtMethod12PrettyMethodEPS0_b", nullptr));
    
    if (func == nullptr) {
        xdl_close(handle);
        logw("[!] Failed to find PrettyMethod symbol");
        return GetPrettyMethod(with_signature);
    }
    
    std::string result;
    func(this, &result, with_signature);
    xdl_close(handle);

    return result;
}

// std::string JniShortName()
// _ZN3art9ArtMethod12JniShortNameEv
std::string ArtMethod::JniShortName() const {
    void* handle = xdl_open("libart.so", XDL_DEFAULT);
    if (handle == nullptr) {
        return "";
    }
    
    typedef void (*JniShortNameFunc)(std::string*, const ArtMethod*);
    auto func = reinterpret_cast<JniShortNameFunc>(
        xdl_sym(handle, "_ZN3art9ArtMethod12JniShortNameEv", nullptr));
    
    if (func == nullptr) {
        xdl_close(handle);
        return "";
    }
    
    std::string result;
    func(&result, this);
    xdl_close(handle);

    return result;
}

// std::string JniLongName()
// _ZN3art9ArtMethod11JniLongNameEv
std::string ArtMethod::JniLongName() const {
    void* handle = xdl_open("libart.so", XDL_DEFAULT);
    if (handle == nullptr) {
        return "";
    }
    
    typedef void (*JniLongNameFunc)(std::string*, const ArtMethod*);
    auto func = reinterpret_cast<JniLongNameFunc>(
        xdl_sym(handle, "_ZN3art9ArtMethod11JniLongNameEv", nullptr));
    
    if (func == nullptr) {
        xdl_close(handle);
        return "";
    }
    
    std::string result;
    func(&result, this);
    xdl_close(handle);

    return result;
}

// const char* GetRuntimeMethodName()
// _ZN3art9ArtMethod20GetRuntimeMethodNameEv
const char* ArtMethod::GetRuntimeMethodName() const {
    void* handle = xdl_open("libart.so", XDL_DEFAULT);
    if (handle == nullptr) {
        return nullptr;
    }
    
    typedef const char* (*GetRuntimeMethodNameFunc)(const ArtMethod*);
    auto func = reinterpret_cast<GetRuntimeMethodNameFunc>(
        xdl_sym(handle, "_ZN3art9ArtMethod20GetRuntimeMethodNameEv", nullptr));
    
    if (func == nullptr) {
        xdl_close(handle);
        return nullptr;
    }
    
    const char* result = func(this);
    xdl_close(handle);
    
    return result;
}

// void SetNotIntrinsic()
// _ZN3art9ArtMethod15SetNotIntrinsicEv
void ArtMethod::SetNotIntrinsic() {
    void* handle = xdl_open("libart.so", XDL_DEFAULT);
    if (handle == nullptr) {
        return;
    }
    
    typedef void (*SetNotIntrinsicFunc)(ArtMethod*);
    auto func = reinterpret_cast<SetNotIntrinsicFunc>(
        xdl_sym(handle, "_ZN3art9ArtMethod15SetNotIntrinsicEv", nullptr));
    
    if (func != nullptr) {
        func(this);
    }
    
    xdl_close(handle);
}

// void CopyFrom(ArtMethod* src, PointerSize image_pointer_size)
// _ZN3art9ArtMethod8CopyFromEPS0_NS_11PointerSizeE
void ArtMethod::CopyFromNative(ArtMethod* src, size_t pointer_size) {
    void* handle = xdl_open("libart.so", XDL_DEFAULT);
    if (handle == nullptr) {
        CopyFrom(src);  // Fallback to manual copy
        return;
    }
    
    typedef void (*CopyFromFunc)(ArtMethod*, ArtMethod*, size_t);
    auto func = reinterpret_cast<CopyFromFunc>(
        xdl_sym(handle, "_ZN3art9ArtMethod8CopyFromEPS0_NS_11PointerSizeE", nullptr));
    
    if (func != nullptr) {
        func(this, src, pointer_size);
    } else {
        CopyFrom(src);  // Fallback
    }
    
    xdl_close(handle);
}

// const void* RegisterNative(const void* native_method)
// _ZN3art9ArtMethod14RegisterNativeEPKv
const void* ArtMethod::RegisterNative(const void* native_method) {
    void* handle = xdl_open("libart.so", XDL_DEFAULT);
    if (handle == nullptr) {
        return nullptr;
    }
    
    typedef const void* (*RegisterNativeFunc)(ArtMethod*, const void*);
    auto func = reinterpret_cast<RegisterNativeFunc>(
        xdl_sym(handle, "_ZN3art9ArtMethod14RegisterNativeEPKv", nullptr));
    
    if (func == nullptr) {
        xdl_close(handle);
        return nullptr;
    }
    
    const void* result = func(this, native_method);
    xdl_close(handle);
    
    return result;
}

// void UnregisterNative()
// _ZN3art9ArtMethod16UnregisterNativeEv
void ArtMethod::UnregisterNative() {
    void* handle = xdl_open("libart.so", XDL_DEFAULT);
    if (handle == nullptr) {
        return;
    }
    
    typedef void (*UnregisterNativeFunc)(ArtMethod*);
    auto func = reinterpret_cast<UnregisterNativeFunc>(
        xdl_sym(handle, "_ZN3art9ArtMethod16UnregisterNativeEv", nullptr));
    
    if (func != nullptr) {
        func(this);
    }
    
    xdl_close(handle);
}

// bool HasSameNameAndSignature(ArtMethod* other)
// _ZN3art9ArtMethod23HasSameNameAndSignatureEPS0_
bool ArtMethod::HasSameNameAndSignature(ArtMethod* other) const {
    void* handle = xdl_open("libart.so", XDL_DEFAULT);
    if (handle == nullptr) {
        return IsSameMethod(other);
    }
    
    typedef bool (*HasSameNameAndSignatureFunc)(const ArtMethod*, ArtMethod*);
    auto func = reinterpret_cast<HasSameNameAndSignatureFunc>(
        xdl_sym(handle, "_ZN3art9ArtMethod23HasSameNameAndSignatureEPS0_", nullptr));
    
    if (func == nullptr) {
        xdl_close(handle);
        return IsSameMethod(other);
    }
    
    bool result = func(this, other);
    xdl_close(handle);
    
    return result;
}

// InvokeType GetInvokeType()
// _ZN3art9ArtMethod13GetInvokeTypeEv
uint32_t ArtMethod::GetInvokeType() const {
    void* handle = xdl_open("libart.so", XDL_DEFAULT);
    if (handle == nullptr) {
        return 0;
    }
    
    typedef uint32_t (*GetInvokeTypeFunc)(const ArtMethod*);
    auto func = reinterpret_cast<GetInvokeTypeFunc>(
        xdl_sym(handle, "_ZN3art9ArtMethod13GetInvokeTypeEv", nullptr));
    
    if (func == nullptr) {
        xdl_close(handle);
        return 0;
    }
    
    uint32_t result = func(this);
    xdl_close(handle);
    
    return result;
}

// static size_t NumArgRegisters(const char* shorty)
// _ZN3art9ArtMethod15NumArgRegistersEPKc
size_t ArtMethod::NumArgRegisters(const char* shorty) {
    void* handle = xdl_open("libart.so", XDL_DEFAULT);
    if (handle == nullptr) {
        return 0;
    }
    
    typedef size_t (*NumArgRegistersFunc)(const char*);
    auto func = reinterpret_cast<NumArgRegistersFunc>(
        xdl_sym(handle, "_ZN3art9ArtMethod15NumArgRegistersEPKc", nullptr));
    
    if (func == nullptr) {
        xdl_close(handle);
        return 0;
    }
    
    size_t result = func(shorty);
    xdl_close(handle);
    
    return result;
}

} // namespace art
