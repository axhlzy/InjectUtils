#include "MemoryPatch.hpp"

#ifndef kNO_KEYSTONE
#include "Deps/Keystone/includes/keystone.h"
#endif

MemoryPatch::MemoryPatch()
{
  _pMem = nullptr;
  _address = 0;
  _size = 0;
  _orig_code.clear();
  _patch_code.clear();
}

MemoryPatch::~MemoryPatch()
{
  // clean up
  _orig_code.clear();
  _orig_code.shrink_to_fit();

  _patch_code.clear();
  _patch_code.shrink_to_fit();
}

MemoryPatch::MemoryPatch(IKittyMemOp *pMem, uintptr_t absolute_address, const void *patch_code, size_t patch_size)
{
  _pMem = nullptr;
  _address = 0;
  _size = 0;
  _orig_code.clear();
  _patch_code.clear();

  if (!pMem || !absolute_address || !patch_code || !patch_size)
    return;

  _pMem = pMem;
  _address = absolute_address;
  _size = patch_size;
  _orig_code.resize(patch_size);
  _patch_code.resize(patch_size);

  // initialize patch
  memcpy(&_patch_code[0], patch_code, patch_size);

  // backup current content
  _pMem->Read(_address, &_orig_code[0], _size);
}

bool MemoryPatch::isValid() const
{
  return (_pMem && _address && _size && _orig_code.size() == _size && _patch_code.size() == _size);
}

size_t MemoryPatch::get_PatchSize() const
{
  return _size;
}

uintptr_t MemoryPatch::get_TargetAddress() const
{
  return _address;
}

bool MemoryPatch::Restore()
{
  if (!isValid())
    return false;

  return _pMem->Write(_address, &_orig_code[0], _size);
}

bool MemoryPatch::Modify()
{
  if (!isValid())
    return false;

  return _pMem->Write(_address, &_patch_code[0], _size);
}

std::string MemoryPatch::get_CurrBytes() const
{
  if (!isValid())
    return "";

  std::vector<uint8_t> buffer(_size);
  _pMem->Read(_address, &buffer[0], _size);

  return KittyUtils::data2Hex(&buffer[0], _size);
}

std::string MemoryPatch::get_OrigBytes() const
{
  if (!isValid())
    return "";

  return KittyUtils::data2Hex(&_orig_code[0], _orig_code.size());
}

std::string MemoryPatch::get_PatchBytes() const
{
  if (!isValid())
    return "";

  return KittyUtils::data2Hex(&_patch_code[0], _patch_code.size());
}

/* ============================== MemoryPatchMgr ============================== */

MemoryPatch MemoryPatchMgr::createWithBytes(uintptr_t absolute_address, const void *patch_code, size_t patch_size)
{
  return MemoryPatch(_pMem, absolute_address, patch_code, patch_size);
}

MemoryPatch MemoryPatchMgr::createWithBytes(const KittyMemoryEx::ProcMap &map, uintptr_t address, const void *patch_code, size_t patch_size)
{
  if (!address || !map.isValid())
    return MemoryPatch();

  return MemoryPatch(_pMem, map.startAddress + address, patch_code, patch_size);
}

MemoryPatch MemoryPatchMgr::createWithHex(uintptr_t absolute_address, std::string hex)
{
  if (!absolute_address || !KittyUtils::String::ValidateHex(hex))
    return MemoryPatch();

  std::vector<uint8_t> patch_code(hex.length() / 2);
  KittyUtils::dataFromHex(hex, &patch_code[0]);

  return MemoryPatch(_pMem, absolute_address, patch_code.data(), patch_code.size());
}

MemoryPatch MemoryPatchMgr::createWithHex(const KittyMemoryEx::ProcMap &map, uintptr_t address, const std::string &hex)
{
  if (!address || !map.isValid())
    return MemoryPatch();

  return createWithHex(map.startAddress + address, hex);
}

#ifndef kNO_KEYSTONE

MemoryPatch MemoryPatchMgr::createWithAsm(uintptr_t absolute_address, MP_ASM_ARCH asm_arch, const std::string &asm_code, uintptr_t asm_address)
{
  MemoryPatch patch;

  if (!absolute_address || asm_code.empty())
    return patch;

  ks_engine *ks = nullptr;
  ks_err err = KS_ERR_ARCH;

  switch (asm_arch)
  {
  case MP_ASM_ARM32:
    err = ks_open(KS_ARCH_ARM, KS_MODE_LITTLE_ENDIAN, &ks);
    break;
  case MP_ASM_ARM64:
    err = ks_open(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, &ks);
    break;
  case MP_ASM_x86:
    err = ks_open(KS_ARCH_X86, KS_MODE_32, &ks);
    break;
  case MP_ASM_x86_64:
    err = ks_open(KS_ARCH_X86, KS_MODE_64, &ks);
    break;
  default:
    KITTY_LOGE("Unknown MP_ASM_ARCH '%d'.", asm_arch);
    return patch;
  }

  if (err != KS_ERR_OK)
  {
    KITTY_LOGE("ks_open failed with error = '%s'.", ks_strerror(err));
    return patch;
  }

  unsigned char *insn_bytes = nullptr;
  size_t insn_count = 0, insn_size = 0;
  int rt = ks_asm(ks, asm_code.c_str(), asm_address, &insn_bytes, &insn_size, &insn_count);

  if (rt == 0 && insn_bytes != nullptr && insn_size)
  {
    patch = MemoryPatch(_pMem, absolute_address, insn_bytes, insn_size);
  }

  if (insn_bytes != nullptr)
  {
    ks_free(insn_bytes);
  }

  ks_close(ks);

  if (rt)
  {
    KITTY_LOGE("ks_asm failed (asm: %s, count = %zu, error = '%s') (code = %u).", asm_code.c_str(), insn_count, ks_strerror(ks_errno(ks)), ks_errno(ks));
  }

  return patch;
}

MemoryPatch MemoryPatchMgr::createWithAsm(const KittyMemoryEx::ProcMap &map, uintptr_t address, MP_ASM_ARCH asm_arch, const std::string &asm_code, uintptr_t asm_address)
{
  if (!address || !map.isValid())
    return MemoryPatch();

  return createWithAsm(map.startAddress + address, asm_arch, asm_code, asm_address);
}

#endif // kNO_KEYSTONE