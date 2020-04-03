#include "efiUtils.h"

static const char plugin_name[] = "efiXplorer";

void setGuidStructure(ea_t ea) {
    static const char struct_name[] = "_EFI_GUID";
    struc_t *sptr = get_struc(get_struc_id(struct_name));
    if (sptr == NULL) {
        sptr = get_struc(add_struc(-1, struct_name));
        if (sptr == NULL)
            return;
        add_struc_member(sptr, "data1", -1, dword_flag(), NULL, 4);
        add_struc_member(sptr, "data2", -1, word_flag(), NULL, 2);
        add_struc_member(sptr, "data3", -1, word_flag(), NULL, 2);
        add_struc_member(sptr, "data4", -1, byte_flag(), NULL, 8);
    }
    size_t size = get_struc_size(sptr);
    create_struct(ea, size, sptr->id);
}

uint8_t getFileType() {
    char fileType[256] = {};
    get_file_type_name(fileType, 256);
    string fileTypeStr = (string)fileType;
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
