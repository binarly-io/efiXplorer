/* efiUtils.cpp
 * This file is part of efiXplorer
 */

#include "efiUtils.h"
#include "tables/efi_system_tables.h"

static const char plugin_name[] = "efiXplorer";

//--------------------------------------------------------------------------
// Create EFI_GUID structure
void setGuidStructure(ea_t ea) {
    static const char struct_name[] = "_EFI_GUID";
    struc_t *sptr = get_struc(get_struc_id(struct_name));
    if (sptr == nullptr) {
        sptr = get_struc(add_struc(-1, struct_name));
        if (sptr == nullptr)
            return;
        add_struc_member(sptr, "data1", -1, dword_flag(), NULL, 4);
        add_struc_member(sptr, "data2", -1, word_flag(), NULL, 2);
        add_struc_member(sptr, "data3", -1, word_flag(), NULL, 2);
        add_struc_member(sptr, "data4", -1, byte_flag(), NULL, 8);
    }
    size_t size = get_struc_size(sptr);
    create_struct(ea, size, sptr->id);
}

//--------------------------------------------------------------------------
// Get input file type (X64 or X86)
uint8_t getFileType() {
    char fileType[256] = {};
    get_file_type_name(fileType, 256);
    auto fileTypeStr = static_cast<string>(fileType);
    int index = fileTypeStr.find("AMD64");
    if (index > 0) {
        /* Portable executable for AMD64 (PE) */
        return X64;
    }
    index = fileTypeStr.find("80386");
    if (index > 0) {
        /* Portable executable for 80386 (PE) */
        return X86;
    }
    return 0;
}

//--------------------------------------------------------------------------
// Get boot service description comment
string getBsComment(ea_t offset, size_t arch) {
    ea_t offset_arch;
    string cmt = "";
    cmt += "gBS->";
    for (auto i = 0; i < BTABLE_LEN; i++) {
        offset_arch = (ea_t)boot_services_table[i].offset64;
        if (arch == X86) {
            offset_arch = (ea_t)boot_services_table[i].offset86;
        }
        if (offset == offset_arch) {
            cmt += boot_services_table[i].name;
            cmt += "()\n";
            cmt += boot_services_table[i].prototype;
            cmt += "\n";
            cmt += boot_services_table[i].parameters;
            break;
        }
    }
    return cmt;
}

//--------------------------------------------------------------------------
// Get runtime service description comment
string getRtComment(ea_t offset, size_t arch) {
    ea_t offset_arch;
    string cmt = "";
    cmt += "gRT->";
    for (auto i = 0; i < RTABLE_LEN; i++) {
        offset_arch = (ea_t)runtime_services_table[i].offset64;
        if (arch == X86) {
            offset_arch = (ea_t)runtime_services_table[i].offset86;
        }
        if (offset == offset_arch) {
            cmt += runtime_services_table[i].name;
            cmt += "()\n";
            cmt += runtime_services_table[i].prototype;
            cmt += "\n";
            cmt += runtime_services_table[i].parameters;
            break;
        }
    }
    return cmt;
}

//--------------------------------------------------------------------------
// Get all data xrefs for address
vector<ea_t> getXrefs(ea_t addr) {
    vector<ea_t> xrefs;
    ea_t xref = get_first_dref_to(addr);
    while (xref != BADADDR) {
        xrefs.push_back(xref);
        xref = get_next_dref_to(addr, xref);
    }
    return xrefs;
}
