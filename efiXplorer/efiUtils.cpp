/*
 * efiXplorer
 * Copyright (C) 2020-2021 Binarly
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 * efiUtils.cpp
 *
 */

#include "efiUtils.h"
#include "efiPluginArgs.h"
#include "tables/efi_system_tables.h"

struct pei_services_entry {
    char name[256];
    uint32_t offset;
    char description[1024];
    uint32_t nr_args;
    char prototype[512];
    uint32_t count;
    uint16_t ppi_guid_push_number;
    uint16_t guid_offset;
};

extern struct pei_services_entry pei_services_table[];
extern size_t pei_services_table_size;

struct variable_ppi_entry {
    char name[256];
    uint32_t offset;
    char description[1024];
    uint32_t nr_args;
    char prototype[512];
};

extern struct variable_ppi_entry variable_ppi_table[];
extern size_t variable_ppi_table_size;

static const char plugin_name[] = "efiXplorer";

//--------------------------------------------------------------------------
// Create EFI_GUID structure
void createGuidStructure(ea_t ea) {
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
    asize_t size = get_struc_size(sptr);
    create_struct(ea, size, sptr->id);
}

//--------------------------------------------------------------------------
// Set EFI_GUID type
void setGuidType(ea_t ea) {
    tinfo_t tinfo;
    if (tinfo.get_named_type(get_idati(), "EFI_GUID")) {
        apply_tinfo(ea, tinfo, TINFO_DEFINITE);
    }
}

//--------------------------------------------------------------------------
// Set type and name
void setTypeAndName(ea_t ea, std::string name, std::string type) {
    set_name(ea, name.c_str(), SN_FORCE);
    tinfo_t tinfo;
    if (tinfo.get_named_type(get_idati(), type.c_str())) {
        apply_tinfo(ea, tinfo, TINFO_DEFINITE);
    }
}

//--------------------------------------------------------------------------
// Get input file type (64-bit, 32-bit image or UEFI firmware)
uint8_t getArch() {
    char fileType[256] = {};
    get_file_type_name(fileType, 256);
    auto fileTypeStr = static_cast<std::string>(fileType);
    size_t index = fileTypeStr.find("AMD64");
    if (index != std::string::npos) {
        // Portable executable for AMD64 (PE)
        return X64;
    }
    index = fileTypeStr.find("80386");
    if (index != std::string::npos) {
        // Portable executable for 80386 (PE)
        return X86;
    }
    index = fileTypeStr.find("UEFI");
    if (index != std::string::npos) {
        // UEFI firmware
        return UEFI;
    }
    return 0;
}

//--------------------------------------------------------------------------
// Get input file type (PEI or DXE-like). No reliable way to determine FFS
// file type given only its PE/TE image section, so hello heuristics
uint8_t guessFileType(uint8_t arch, std::vector<json> *allGuids) {
    if (arch == UEFI) {
        return FTYPE_DXE_AND_THE_LIKE;
    }
    segment_t *hdr_seg = get_segm_by_name("HEADER");
    if (hdr_seg == NULL) {
        return FTYPE_DXE_AND_THE_LIKE;
    }
    uint64_t signature = get_wide_word(hdr_seg->start_ea);
    bool hasPeiGuids = false;
    for (auto guid = allGuids->begin(); guid != allGuids->end(); guid++) {
        json guidVal = *guid;

        if (static_cast<std::string>(guidVal["name"]).find("PEI") != std::string::npos ||
            static_cast<std::string>(guidVal["name"]).find("Pei") != std::string::npos) {
            hasPeiGuids = true;
            break;
        }
    }

    bool hasPeiInPath = false;
    char fileName[0x1000] = {0};
    get_input_file_path(fileName, sizeof(fileName));
    auto fileNameStr = static_cast<std::string>(fileName);
    if ((fileNameStr.find("Pei") != std::string::npos ||
         fileNameStr.find("pei") != std::string::npos || signature == VZ) &&
        arch == X86) {
        hasPeiInPath = true;
    }

    if (arch == X86 && (signature == VZ || hasPeiGuids)) {
        msg("[%s] Parsing binary file as PEI, signature = %lx, hasPeiGuids = %d\n",
            plugin_name, signature, hasPeiGuids);
        return FTYPE_PEI;
    } else {
        msg("[%s] Parsing binary file as DXE/SMM, signature = %lx, hasPeiGuids = %d\n",
            plugin_name, signature, hasPeiGuids);
        return FTYPE_DXE_AND_THE_LIKE;
    }
}

uint8_t getFileType(std::vector<json> *allGuids) {
    uint8_t arch = getArch();
    if (arch == UEFI || g_args.disable_ui) {
        // Skip UI for efiXloader or if disable_ui argument passed
        return FTYPE_DXE_AND_THE_LIKE;
    }
    auto ftype = guessFileType(arch, allGuids);
    auto btnId =
        ask_buttons("DXE/SMM", "PEI", "", ftype == FTYPE_DXE_AND_THE_LIKE,
                    "Parse file as", ftype == FTYPE_DXE_AND_THE_LIKE ? "DXE/SMM" : "PEI");
    if (btnId == ASKBTN_YES) {
        return FTYPE_DXE_AND_THE_LIKE;
    } else {
        return FTYPE_PEI;
    }
}

//--------------------------------------------------------------------------
// Get boot service description comment
std::string getBsComment(uint32_t offset, uint8_t arch) {
    uint32_t offset_current;
    std::string cmt = "gBS->";
    for (auto i = 0; i < BTABLE_LEN; i++) {
        offset_current = boot_services_table[i].offset64;
        if (arch == X86) {
            offset_current = boot_services_table[i].offset32;
        }
        if (offset == offset_current) {
            cmt += static_cast<std::string>(boot_services_table[i].name) + "()\n" +
                   static_cast<std::string>(boot_services_table[i].prototype) + "\n" +
                   static_cast<std::string>(boot_services_table[i].parameters);
            break;
        }
    }
    return cmt;
}

//--------------------------------------------------------------------------
// Get Pei service description comment (X86 is assumed)
std::string getPeiSvcComment(uint32_t offset) {
    std::string cmt = "gPS->";
    for (auto i = 0; i < pei_services_table_size; i++) {
        if (offset == pei_services_table[i].offset) {
            cmt += static_cast<std::string>(pei_services_table[i].name) + "()\n" +
                   static_cast<std::string>(pei_services_table[i].prototype);
            break;
        }
    }
    return cmt;
}

//--------------------------------------------------------------------------
// Get PPI service description comment (X86 is assumed)
std::string getPPICallComment(uint32_t offset, std::string name) {
    std::string cmt = name + "->"; // VariablePpi
    for (auto i = 0; i < variable_ppi_table_size; i++) {
        if (offset == variable_ppi_table[i].offset) {
            cmt += static_cast<std::string>(variable_ppi_table[i].name) + "()\n" +
                   static_cast<std::string>(variable_ppi_table[i].prototype);
            break;
        }
    }
    return cmt;
}

//--------------------------------------------------------------------------
// Get SMM service description comment
std::string getSmmVarComment() {
    std::string name = "EFI_SMM_VARIABLE_PROTOCOL";
    std::string prototype = "EFI_STATUS (EFIAPI *EFI_GET_VARIABLE)"
                            "(IN CHAR16 *VariableName, "
                            "IN EFI_GUID *VendorGuid, "
                            "OUT UINT32 *Attributes, OPTIONAL "
                            "IN OUT UINTN *DataSize, "
                            "OUT VOID *Data OPTIONAL);";

    std::string cmt = name + "->SmmGetVariable()\n" + prototype;
    return cmt;
}

//--------------------------------------------------------------------------
// Get runtime service description comment
std::string getRtComment(uint32_t offset, uint8_t arch) {
    ea_t offset_arch;
    std::string cmt = "gRT->";
    for (auto i = 0; i < RTABLE_LEN; i++) {
        offset_arch = runtime_services_table[i].offset64;
        if (arch == X86) {
            offset_arch = runtime_services_table[i].offset32;
        }
        if (offset == offset_arch) {
            cmt += static_cast<std::string>(runtime_services_table[i].name) + "()\n" +
                   static_cast<std::string>(runtime_services_table[i].prototype) + "\n" +
                   static_cast<std::string>(runtime_services_table[i].parameters);
            break;
        }
    }
    return cmt;
}

//--------------------------------------------------------------------------
// Find address of global gBS var for X64 module for each service
ea_t findUnknownBsVarX64(ea_t ea) {
    ea_t resAddr = 0;
    insn_t insn;

    // Check 10 instructions below
    for (int i = 0; i < 10; i++) {
        decode_insn(&insn, ea);
        if (insn.itype == NN_mov && insn.ops[0].type == o_reg &&
            insn.ops[0].reg == REG_RAX && insn.ops[1].type == o_mem) {
            msg("[%s] found gBS at 0x%016llX, address = 0x%016llX\n", plugin_name,
                static_cast<uint64_t>(ea), static_cast<uint64_t>(insn.ops[1].addr));
            resAddr = insn.ops[1].addr;
            set_cmt(ea, "EFI_BOOT_SERVICES *gBS", true);
            break;
        }
        ea = prev_head(ea, 0);
    }
    return resAddr;
}

//--------------------------------------------------------------------------
// Get all xrefs for given address
std::vector<ea_t> getXrefs(ea_t addr) {
    std::vector<ea_t> xrefs;
    ea_t xref = get_first_dref_to(addr);
    while (xref != BADADDR) {
        xrefs.push_back(xref);
        xref = get_next_dref_to(addr, xref);
    }
    return xrefs;
}

//--------------------------------------------------------------------------
// Wrapper for op_stroff function
bool opStroff(ea_t addr, std::string type) {
    insn_t insn;
    decode_insn(&insn, addr);
    tid_t struc_id = get_struc_id(type.c_str());
    return op_stroff(insn, 0, &struc_id, 1, 0);
}

//--------------------------------------------------------------------------
// Get pointer to named type and apply it
bool setPtrType(ea_t addr, std::string type) {
    tinfo_t tinfo;
    if (!tinfo.get_named_type(get_idati(), type.c_str())) {
        return false;
    }
    tinfo_t ptrTinfo;
    ptrTinfo.create_ptr(tinfo);
    apply_tinfo(addr, ptrTinfo, TINFO_DEFINITE);
    return true;
}

//--------------------------------------------------------------------------
// Set name and apply pointer to named type
void setPtrTypeAndName(ea_t ea, std::string name, std::string type) {
    set_name(ea, name.c_str(), SN_FORCE);
    setPtrType(ea, type.c_str());
}

//--------------------------------------------------------------------------
// Check for guids.json file exist
bool guidsJsonExists() { return !getGuidsJsonFile().empty(); }

//--------------------------------------------------------------------------
// Get guids.json file name
std::filesystem::path getGuidsJsonFile() {
    std::filesystem::path guidsJsonPath;
    guidsJsonPath /= idadir("plugins");
    guidsJsonPath /= "guids";
    guidsJsonPath /= "guids.json";
    if (std::filesystem::exists(guidsJsonPath)) {
        return guidsJsonPath;
    }

    // Try to load it from the per-user directory.
    guidsJsonPath.clear();
    guidsJsonPath /= get_user_idadir();
    guidsJsonPath /= "plugins";
    guidsJsonPath /= "guids";
    guidsJsonPath /= "guids.json";
    if (std::filesystem::exists(guidsJsonPath)) {
        return guidsJsonPath;
    }

    // Does not exist.
    guidsJsonPath.clear();
    return guidsJsonPath;
}

//--------------------------------------------------------------------------
// Get json summary file name
std::filesystem::path getSummaryFile() {
    std::string idbPath;
    idbPath = get_path(PATH_TYPE_IDB);
    std::filesystem::path logFile;
    logFile /= idbPath;
    logFile.replace_extension(".json");
    return logFile;
}

//--------------------------------------------------------------------------
// Check for summary json file exist
bool summaryJsonExist() {
    std::string idbPath;
    idbPath = get_path(PATH_TYPE_IDB);
    std::filesystem::path logFile;
    logFile /= idbPath;
    logFile.replace_extension(".json");
    return std::filesystem::exists(logFile);
}

//--------------------------------------------------------------------------
// Change EFI_SYSTEM_TABLE *SystemTable to EFI_PEI_SERVICES **PeiService
// for ModuleEntryPoint
void setEntryArgToPeiSvc() {
    for (auto idx = 0; idx < get_entry_qty(); idx++) {
        uval_t ord = get_entry_ordinal(idx);
        ea_t start_ea = get_entry(ord);
        tinfo_t tif_ea;
        if (guess_tinfo(&tif_ea, start_ea) == GUESS_FUNC_FAILED) {
            msg("[%s] guess_tinfo failed, start_ea = 0x%016llX, idx=%d\n", plugin_name,
                static_cast<uint64_t>(start_ea), idx);
            continue;
        }
        func_type_data_t funcdata;
        if (!tif_ea.get_func_details(&funcdata)) {
            msg("[%s] get_func_details failed, %d\n", plugin_name, idx);
            continue;
        }
        tinfo_t tif_pei;
        bool res = tif_pei.get_named_type(get_idati(), "EFI_PEI_SERVICES");
        if (!res) {
            msg("[%s] get_named_type failed, res = %d, idx=%d\n", plugin_name, res, idx);
            continue;
        }
        tinfo_t ptrTinfo;
        tinfo_t ptrPtrTinfo;
        ptrTinfo.create_ptr(tif_pei);
        ptrPtrTinfo.create_ptr(ptrTinfo);
        if (funcdata.size() == 2) {
            funcdata[1].type = ptrPtrTinfo;
            funcdata[1].name = "PeiServices";
            tinfo_t func_tinfo;
            if (!func_tinfo.create_func(funcdata)) {
                msg("[%s] create_func failed, idx=%d\n", plugin_name, idx);
                continue;
            }
            if (!apply_tinfo(start_ea, func_tinfo, TINFO_DEFINITE)) {
                msg("[%s] get_named_type failed, idx=%d\n", plugin_name, idx);
                continue;
            }
        }
    }
}

//--------------------------------------------------------------------------
// Change the value of a number to match the data type
uval_t truncImmToDtype(uval_t value, op_dtype_t dtype) {
    switch (dtype) {
    case dt_byte:
        return value & ((1 << 8) - 1);
    case dt_word:
        return value & ((1 << 16) - 1);
    case dt_dword:
        return value & (((uval_t)1 << 32) - 1);
    default:
        return value;
    }
}

//--------------------------------------------------------------------------
// Get module name by address
qstring getModuleNameLoader(ea_t address) {
    segment_t *seg = getseg(address);
    qstring seg_name;
    get_segm_name(&seg_name, seg);
    return seg_name.remove(seg_name.size() - 7, seg_name.size());
}

//--------------------------------------------------------------------------
// Get GUID data by address
json getGuidByAddr(ea_t addr) {
    return json::array(
        {get_wide_dword(addr), get_wide_word(addr + 4), get_wide_word(addr + 6),
         get_wide_byte(addr + 8), get_wide_byte(addr + 9), get_wide_byte(addr + 10),
         get_wide_byte(addr + 11), get_wide_byte(addr + 12), get_wide_byte(addr + 13),
         get_wide_byte(addr + 14), get_wide_byte(addr + 15)});
}

//--------------------------------------------------------------------------
// Validate GUID value
bool checkGuid(json guid) {
    if (static_cast<uint32_t>(guid[0]) == 0x00000000 && (uint16_t)guid[1] == 0x0000) {
        return false;
    }
    if (static_cast<uint32_t>(guid[0]) == 0xffffffff && (uint16_t)guid[1] == 0xffff) {
        return false;
    }
    return true;
}

//--------------------------------------------------------------------------
// Convert GUID value to string
std::string getGuidFromValue(json guid) {
    char guidStr[37] = {0};
    snprintf(guidStr, 37, "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
             static_cast<uint32_t>(guid[0]), static_cast<uint16_t>(guid[1]),
             static_cast<uint16_t>(guid[2]), static_cast<uint8_t>(guid[3]),
             static_cast<uint8_t>(guid[4]), static_cast<uint8_t>(guid[5]),
             static_cast<uint8_t>(guid[6]), static_cast<uint8_t>(guid[7]),
             static_cast<uint8_t>(guid[8]), static_cast<uint8_t>(guid[9]),
             static_cast<uint8_t>(guid[10]));
    return static_cast<std::string>(guidStr);
}

//--------------------------------------------------------------------------
// Convert 64-bit value to hex string
std::string getHex(uint64_t value) {
    char hexstr[21] = {};
    snprintf(hexstr, 21, "%llX", value);
    return static_cast<std::string>(hexstr);
}

//--------------------------------------------------------------------------
// Make sure the first argument looks like protocol
bool bootServiceProtCheck(ea_t callAddr) {
    bool valid = false;
    insn_t insn;
    auto addr = prev_head(callAddr, 0);
    decode_insn(&insn, addr);
    while (!is_basic_block_end(insn, false)) {

        // for next iteration
        decode_insn(&insn, addr);
        addr = prev_head(addr, 0);

        // check current instruction
        if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
            insn.ops[0].reg == REG_RCX) {
            if (insn.ops[1].type == o_mem) {
                // will still be a false positive if the Handle in
                // SmmInstallProtocolInterface is a global variable)
                valid = true;
            }
            break;
        }
    }
    return valid;
}

bool markCopy(ea_t codeAddr, ea_t varAddr, std::string type) {
    insn_t insn;
    int reg = -1;
    ea_t ea = codeAddr;
    ea_t varCopy = BADADDR;
    for (auto i = 0; i < 16; ++i) {
        decode_insn(&insn, ea);

        // get `reg` value
        if (insn.itype == NN_mov && insn.ops[0].type == o_reg &&
            insn.ops[1].type == o_mem && insn.ops[1].addr == varAddr) {
            reg = insn.ops[0].value;
        }

        // get `varCopy`
        if (reg > -1 && insn.itype == NN_mov && insn.ops[0].type == o_mem &&
            insn.ops[1].type == o_reg && insn.ops[1].value == reg) {
            varCopy = insn.ops[0].addr;
            break;
        }

        // minimize FP (register value override)
        if (reg > -1 && insn.ops[0].type == o_reg && insn.ops[0].value == reg &&
            insn.ops[1].addr != varAddr) {
            break;
        }

        ea = next_head(ea, BADADDR);
    }

    if (varCopy == BADADDR) {
        return false;
    }

    std::string name;

    if (type == std::string("gSmst")) {
        setPtrTypeAndName(varCopy, "gSmst", "_EFI_SMM_SYSTEM_TABLE2");
    }

    if (type == std::string("gBS")) {
        setPtrTypeAndName(varCopy, "gBS", "EFI_BOOT_SERVICES");
    }

    if (type == std::string("gRT")) {
        setPtrTypeAndName(varCopy, "gRT", "EFI_RUNTIME_SERVICES");
    }

    return true;
}

bool markCopiesForGlobalVars(std::vector<ea_t> globalVars, std::string type) {
    for (auto var : globalVars) {
        auto xrefs = getXrefs(var);
        for (auto addr : xrefs) {
            markCopy(addr, var, type);
        }
    }
    return true;
}

//--------------------------------------------------------------------------
// Generate name string from type
std::string typeToName(std::string type) {
    std::string result;
    size_t counter = 0;
    for (char const &c : type) {
        if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
            result.push_back(c);
            counter += 1;
            continue;
        }

        if (c >= 'A' && c <= 'Z') {
            if (counter > 0) {
                result.push_back(c + 32);
            } else
                result.push_back(c);
            counter += 1;
            continue;
        }

        if (c == '_') {
            counter = 0;
        } else {
            counter += 1;
        }
    }
    return result;
}

xreflist_t xrefsToStackVar(ea_t funcEa, qstring varName) {
    struc_t *frame = get_frame(funcEa);
    func_t *func = get_func(funcEa);
    member_t member; // Get member by name
    bool found = false;
    for (int i = 0; i < frame->memqty; i++) {
        member = frame->members[i];
        qstring name;
        get_member_name(&name, frame->members[i].id);
        if (name == varName) {
            found = true;
            break;
        }
    }
    xreflist_t xrefs_list; // Get xrefs
    if (found) {
        build_stkvar_xrefs(&xrefs_list, func, &member);
    }
    return xrefs_list;
}

void opstroffForAddress(ea_t ea, qstring typeName) {
    insn_t insn;
    for (auto i = 0; i < 16; i++) {
        ea = next_head(ea, BADADDR);
        decode_insn(&insn, ea);
        // Found interface function call
        if ((insn.itype == NN_call || insn.itype == NN_callfi ||
             insn.itype == NN_callni) &&
            (insn.ops[0].type == o_displ || insn.ops[0].type == o_phrase) &&
            insn.ops[0].reg == REG_RAX) {
            opStroff(ea, static_cast<std::string>(typeName.c_str()));
            msg("[%s] Mark arguments at address 0x%016llX (interface type: %s)\n",
                plugin_name, static_cast<uint64_t>(ea), typeName.c_str());
            break;
        }
        // If the RAX value is overridden
        if (insn.ops[0].reg == REG_RAX) {
            break;
        }
    }
}

//--------------------------------------------------------------------------
// Mark the arguments of each function from an interface derived from
// a local variable
void opstroffForInterface(xreflist_t localXrefs, qstring typeName) {
    insn_t insn;
    for (auto xref : localXrefs) {
        decode_insn(&insn, xref.ea);
        if (insn.itype == NN_mov && insn.ops[0].reg == REG_RAX) {
            opstroffForAddress(xref.ea, typeName);
        }
    }
}

//--------------------------------------------------------------------------
// Mark the arguments of each function from an interface derived from
// a global variable
void opstroffForGlobalInterface(std::vector<ea_t> xrefs, qstring typeName) {
    insn_t insn;
    for (auto ea : xrefs) {
        decode_insn(&insn, ea);
        if (insn.itype == NN_mov && insn.ops[0].reg == REG_RAX) {
            opstroffForAddress(ea, typeName);
        }
    }
}

bool addrInVec(std::vector<ea_t> vec, ea_t addr) {
    return find(vec.begin(), vec.end(), addr) != vec.end();
}

bool addrInTables(std::vector<ea_t> gStList, std::vector<ea_t> gBsList,
                  std::vector<ea_t> gRtList, ea_t ea) {
    return (addrInVec(gStList, ea) || addrInVec(gBsList, ea) || addrInVec(gRtList, ea));
}
