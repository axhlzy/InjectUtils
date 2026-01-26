#ifndef ART_COMMON_H
#define ART_COMMON_H

#include <cstdint>
#include <cstddef>

namespace art {

// 类型定义
using int16_t = short;
using uint16_t = unsigned short;
using uint32_t = unsigned int;
using int64_t = long long;
using uint64_t = unsigned long long;

// 指针大小（根据架构）
constexpr size_t PointerSize = sizeof(void*);

// GcRoot 大小（压缩引用）
constexpr size_t GcRootSize = 4;

// 访问标志常量 (Access Flags)
namespace AccessFlags {
    constexpr uint32_t kAccPublic = 0x0001;
    constexpr uint32_t kAccPrivate = 0x0002;
    constexpr uint32_t kAccProtected = 0x0004;
    constexpr uint32_t kAccStatic = 0x0008;
    constexpr uint32_t kAccFinal = 0x0010;
    constexpr uint32_t kAccSynchronized = 0x0020;
    constexpr uint32_t kAccBridge = 0x0040;
    constexpr uint32_t kAccVarargs = 0x0080;
    constexpr uint32_t kAccNative = 0x0100;
    constexpr uint32_t kAccInterface = 0x0200;
    constexpr uint32_t kAccAbstract = 0x0400;
    constexpr uint32_t kAccStrict = 0x0800;
    constexpr uint32_t kAccSynthetic = 0x1000;
    constexpr uint32_t kAccAnnotation = 0x2000;
    constexpr uint32_t kAccEnum = 0x4000;
    constexpr uint32_t kAccConstructor = 0x00010000;
    constexpr uint32_t kAccDeclaredSynchronized = 0x00020000;
    constexpr uint32_t kAccObsoleteMethod = 0x00040000;
    constexpr uint32_t kAccIntrinsic = 0x80000000;
}

// GcRoot 辅助类模板
template<typename T>
class GcRoot {
public:
    static constexpr size_t Size = GcRootSize;
    
    explicit GcRoot(void* addr) : address_(reinterpret_cast<uintptr_t>(addr)) {}
    
    T* Read() const {
        uint32_t ref = *reinterpret_cast<uint32_t*>(address_);
        // 简化处理：假设压缩引用直接是指针（实际需要解压缩）
        return reinterpret_cast<T*>(static_cast<uintptr_t>(ref));
    }
    
    uint32_t GetReference() const {
        return *reinterpret_cast<uint32_t*>(address_);
    }
    
private:
    uintptr_t address_;
};

// 前向声明
class ArtMethod;
class ShadowFrame;
class ArtClass;
class DexFile;
class DexCache;

} // namespace art

#endif // ART_COMMON_H
