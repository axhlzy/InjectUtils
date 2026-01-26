#ifndef ART_METHOD_H
#define ART_METHOD_H

#include "art_common.h"
#include <string>
#include <jvmti.h>

namespace art {

// 前向声明
class DexFile;

/**
 * ArtMethod 类
 * 参考: art/runtime/art_method.h
 * 
 * 内存布局:
 * Offset  Size  Field
 * ------  ----  -----
 * 0x00    0x04  GcRoot<mirror::Class> declaring_class_
 * 0x04    0x04  std::atomic<std::uint32_t> access_flags_
 * 0x08    0x04  uint32_t dex_code_item_offset_
 * 0x0C    0x04  uint32_t dex_method_index_
 * 0x10    0x02  uint16_t method_index_
 * 0x12    0x02  union { uint16_t hotness_count_; uint16_t imt_index_; }
 * 0x14    PTR   void* data_
 * 0x14+P  PTR   void* entry_point_from_quick_compiled_code_
 */
class ArtMethod {
private:
    uintptr_t GetFieldAddress(size_t offset) const {
        return reinterpret_cast<uintptr_t>(this) + offset;
    }
    
public:
    // ========== 字段地址获取 ==========
    uint32_t* GetDeclaringClassPtr();
    uint32_t* GetAccessFlagsPtr();
    uint32_t* GetDexCodeItemOffsetPtr();
    uint32_t* GetDexMethodIndexPtr();
    uint16_t* GetMethodIndexPtr();
    uint16_t* GetHotnessCountPtr();
    uint16_t* GetImtIndexPtr();
    void** GetDataPtr();
    void** GetEntryPointFromQuickCompiledCodePtr();
    
    // ========== Getter 方法 ==========
    uint32_t GetDeclaringClassRef() const;
    uint32_t GetAccessFlags() const;
    uint32_t GetDexCodeItemOffset() const;
    uint32_t GetDexMethodIndex() const;
    uint16_t GetMethodIndex() const;
    uint16_t GetHotnessCount() const;
    uint16_t GetImtIndex() const;
    void* GetData() const;
    void* GetJniCode() const;
    void* GetEntryPointFromQuickCompiledCode() const;
    
    // ========== Setter 方法 ==========
    void SetAccessFlags(uint32_t flags);
    void SetDexCodeItemOffset(uint32_t offset);
    void SetDexMethodIndex(uint32_t index);
    void SetMethodIndex(uint16_t index);
    void SetHotnessCount(uint16_t count);
    void SetData(void* data);
    void SetEntryPointFromQuickCompiledCode(void* entry_point);
    
    // ========== 访问标志检查 ==========
    bool IsPublic() const;
    bool IsPrivate() const;
    bool IsProtected() const;
    bool IsStatic() const;
    bool IsFinal() const;
    bool IsSynchronized() const;
    bool IsBridge() const;
    bool IsVarargs() const;
    bool IsNative() const;
    bool IsAbstract() const;
    bool IsStrict() const;
    bool IsSynthetic() const;
    bool IsConstructor() const;
    bool IsDeclaredSynchronized() const;
    bool IsObsolete() const;
    bool IsIntrinsic() const;
    
    // ========== 实用方法 ==========
    void* GetCodeItem(void* dex_file_begin) const;
    bool HasCodeItem() const;
    bool IsJniMethod() const;
    void CopyFrom(const ArtMethod* src);
    bool IsSameMethod(const ArtMethod* other) const;
    
    // 获取 DexFile（通过 DexCache）
    const DexFile* GetDexFile() const;
    
    // ========== 方法信息（通过 JVMTI） ==========
    std::string GetMethodName() const;
    std::string GetDeclaringClassName() const;
    std::string GetPrettyMethod(bool with_signature = true) const;
    std::string GetAccessFlagsString() const;
    
    // ========== 调试方法 ==========
    void Print() const;
    
    // ========== 静态方法 ==========
    static constexpr size_t GetSize() {
        return GcRootSize + 0x10 + PointerSize * 2;
    }
    
    // ========== ART 符号调用（使用 xdl） ==========
    
    // std::string PrettyMethod(bool with_signature)
    // _ZN3art9ArtMethod12PrettyMethodEb
    std::string PrettyMethodNative(bool with_signature = true) const;
    
    // std::string JniShortName()
    // _ZN3art9ArtMethod12JniShortNameEv
    std::string JniShortName() const;
    
    // std::string JniLongName()
    // _ZN3art9ArtMethod11JniLongNameEv
    std::string JniLongName() const;
    
    // const char* GetRuntimeMethodName()
    // _ZN3art9ArtMethod20GetRuntimeMethodNameEv
    const char* GetRuntimeMethodName() const;
    
    // void SetNotIntrinsic()
    // _ZN3art9ArtMethod15SetNotIntrinsicEv
    void SetNotIntrinsic();
    
    // void CopyFrom(ArtMethod* src, PointerSize image_pointer_size)
    // _ZN3art9ArtMethod8CopyFromEPS0_NS_11PointerSizeE
    void CopyFromNative(ArtMethod* src, size_t pointer_size);
    
    // const void* RegisterNative(const void* native_method)
    // _ZN3art9ArtMethod14RegisterNativeEPKv
    const void* RegisterNative(const void* native_method);
    
    // void UnregisterNative()
    // _ZN3art9ArtMethod16UnregisterNativeEv
    void UnregisterNative();
    
    // bool HasSameNameAndSignature(ArtMethod* other)
    // _ZN3art9ArtMethod23HasSameNameAndSignatureEPS0_
    bool HasSameNameAndSignature(ArtMethod* other) const;
    
    // InvokeType GetInvokeType()
    // _ZN3art9ArtMethod13GetInvokeTypeEv
    uint32_t GetInvokeType() const;
    
    // static size_t NumArgRegisters(const char* shorty)
    // _ZN3art9ArtMethod15NumArgRegistersEPKc
    static size_t NumArgRegisters(const char* shorty);
};

} // namespace art

#endif // ART_METHOD_H
