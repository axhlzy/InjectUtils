#include <iostream>
#include <string>

class ShellReader {

public:
    off64_t file_offset_;
    off64_t file_size_;

    ElfW(Ehdr) header_;
    size_t phdr_num_;

    const ElfW(Phdr) * phdr_table_;

    const ElfW(Shdr) * shdr_table_;
    size_t shdr_num_;

    const ElfW(Dyn) * dynamic_;

    const char *strtab_;
    size_t strtab_size_;

    // First page of reserved address space.
    void *load_start_;
    // Size in bytes of reserved address space.
    size_t load_size_;

    // Load bias.
    ElfW(Addr) load_bias_;

    // Loaded phdr.
    const ElfW(Phdr) * loaded_phdr_;

    void *start_addr_;

public:
    ShellReader(off64_t file_offset, off64_t file_size) {
        file_offset_ = file_offset;
        file_size_ = file_size;

        ReadElfHeader();
        ReadProgramHeaders();

        //
    }

private:
    bool ReadElfHeader() {
        return memcpy(&(header_), start_addr_, sizeof(header_));
    }

    bool ReadProgramHeaders() {
        phdr_num_ = header_.e_phnum;
        size_t size = phdr_num_ * sizeof(ElfW(Phdr));

        return true;
    }
}