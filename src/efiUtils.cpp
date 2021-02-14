/*
 *        __ ___   __      _
 *       / _(_) \ / /     | |
 *   ___| |_ _ \ V / _ __ | | ___  _ __ ___ _ __
 *  / _ \  _| | > < | '_ \| |/ _ \| '__/ _ \ '__|
 * |  __/ | | |/ . \| |_) | | (_) | | |  __/ |
 *  \___|_| |_/_/ \_\ .__/|_|\___/|_|  \___|_|
 *                  | |
 *                  |_|
 *
 * efiXplorer
 * Copyright (C) 2020-2021  Binarly
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
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
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
void setTypeAndName(ea_t ea, string name, string type) {
    set_name(ea, name.c_str(), SN_CHECK);
    tinfo_t tinfo;
    if (tinfo.get_named_type(get_idati(), type.c_str())) {
        apply_tinfo(ea, tinfo, TINFO_DEFINITE);
    }
}

//--------------------------------------------------------------------------
// Get input file architecture (bit width X64 or X86)
uint8_t getArch() {
    char fileType[256] = {};
    get_file_type_name(fileType, 256);
    auto fileTypeStr = static_cast<string>(fileType);
    size_t index = fileTypeStr.find("AMD64");
    if (index != string::npos) {
        /* Portable executable for AMD64 (PE) */
        return X64;
    }
    index = fileTypeStr.find("80386");
    if (index != string::npos) {
        /* Portable executable for 80386 (PE) */
        return X86;
    }
    index = fileTypeStr.find("UEFI");
    if (index != string::npos) {
        /* UEFI firmware */
        return UEFI;
    }
    return 0;
}

//--------------------------------------------------------------------------
// Get input file type (PEI or DXE-like). No reliable way to determine FFS
// file type given only its PE/TE image section, so hello heuristics
uint8_t guessFileType(uint8_t arch, vector<json> *allGuids) {
    if (arch == UEFI) {
        return FTYPE_DXE_AND_THE_LIKE;
    }
    segment_t *hdr_seg = get_segm_by_name("HEADER");
    if (hdr_seg == NULL) {
        DEBUG_MSG("[%s] hdr_seg == NULL \n", plugin_name);
        return FTYPE_DXE_AND_THE_LIKE;
    }
    uint64_t signature = get_wide_word(hdr_seg->start_ea);
    bool hasPeiGuids = false;
    for (auto guid = allGuids->begin(); guid != allGuids->end(); guid++) {
        json guidVal = *guid;

        if (static_cast<string>(guidVal["name"]).find("PEI") != string::npos ||
            static_cast<string>(guidVal["name"]).find("Pei") != string::npos) {
            hasPeiGuids = true;
            break;
        }
    }

    bool hasPeiInPath = false;
    char fileName[0x1000] = {0};
    get_input_file_path(fileName, sizeof(fileName));
    auto fileNameStr = static_cast<string>(fileName);
    if ((fileNameStr.find("Pei") != string::npos ||
         fileNameStr.find("pei") != string::npos || signature == VZ) &&
        arch == X86) {
        hasPeiInPath = true;
    }

    if (arch == X86 && (signature == VZ || hasPeiGuids)) {
        DEBUG_MSG("[%s] Parsing binary file as PEI, signature = %x, "
                  "hasPeiGuids = %d\n",
                  plugin_name, signature, hasPeiGuids);
        return FTYPE_PEI;
    } else {
        DEBUG_MSG("[%s] Parsing binary file as DXE/SMM, signature = %x, "
                  "hasPeiGuids = %d\n",
                  plugin_name, signature, hasPeiGuids);
        return FTYPE_DXE_AND_THE_LIKE;
    }
}

uint8_t getFileType(vector<json> *allGuids) {
    uint8_t arch = getArch();
    if (arch == UEFI || g_args.disable_ui) {
        // skip UI for efiXloader or if disable_ui argument passed
        return FTYPE_DXE_AND_THE_LIKE;
    }
    auto ftype = guessFileType(arch, allGuids);
    auto btnId = ask_buttons(
        "DXE/SMM", "PEI", "", ftype == FTYPE_DXE_AND_THE_LIKE, "Parse file as",
        ftype == FTYPE_DXE_AND_THE_LIKE ? "DXE/SMM" : "PEI");
    if (btnId == ASKBTN_YES) {
        return FTYPE_DXE_AND_THE_LIKE;
    } else {
        return FTYPE_PEI;
    }
}

//--------------------------------------------------------------------------
// Get boot service description comment
string getBsComment(ea_t offset, uint8_t arch) {
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
// Get Pei service description comment (X86 is assumed)
string getPeiSvcComment(ea_t offset) {
    string cmt = "";
    cmt += "gPS->";
    for (auto i = 0; i < pei_services_table_size; i++) {
        if (offset == pei_services_table[i].offset) {
            cmt += pei_services_table[i].name;
            cmt += "()\n";
            cmt += pei_services_table[i].prototype;
            break;
        }
    }
    return cmt;
}

//--------------------------------------------------------------------------
// Get PPI service description comment (X86 is assumed)
string getPPICallComment(ea_t offset, string name) {
    string cmt = "";
    cmt += name + "->"; // VariablePpi
    for (auto i = 0; i < variable_ppi_table_size; i++) {
        if (offset == variable_ppi_table[i].offset) {
            cmt += variable_ppi_table[i].name;
            cmt += "()\n";
            cmt += variable_ppi_table[i].prototype;
            break;
        }
    }
    return cmt;
}

//--------------------------------------------------------------------------
// Get SMM service description comment
string getSmmVarComment() {
    ea_t offset = 0;
    string name = "EFI_SMM_VARIABLE_PROTOCOL";
    string prototype = "EFI_STATUS (EFIAPI *EFI_GET_VARIABLE)"
                       "(IN CHAR16 *VariableName, "
                       "IN EFI_GUID *VendorGuid, "
                       "OUT UINT32 *Attributes, OPTIONAL "
                       "IN OUT UINTN *DataSize, "
                       "OUT VOID *Data OPTIONAL);";

    string cmt = "";
    cmt += name + "->";
    cmt += "SmmGetVariable";
    cmt += "()\n";
    cmt += prototype;
    return cmt;
}

//--------------------------------------------------------------------------
// Get runtime service description comment
string getRtComment(ea_t offset, uint8_t arch) {
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
// Find address of global gBS var for X64 module for each service
ea_t findUnknownBsVarX64(ea_t ea) {
    ea_t resAddr = 0;
    insn_t insn;
    /* 10 instructions below */
    for (int i = 0; i < 10; i++) {
        decode_insn(&insn, ea);
        /* check if insn like 'mov rax, cs:<gBS>' */
        if (insn.itype == NN_mov && insn.ops[0].type == o_reg &&
            insn.ops[0].reg == REG_RAX && insn.ops[1].type == o_mem) {
            DEBUG_MSG("[%s] found gBS at 0x%016X, address = 0x%016X\n",
                      plugin_name, ea, insn.ops[1].addr);
            resAddr = insn.ops[1].addr;
            set_cmt(ea, "EFI_BOOT_SERVICES *gBS", true);
            break;
        }
        ea = prev_head(ea, 0);
    }
    return resAddr;
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

//--------------------------------------------------------------------------
// op_stroff wrapper
bool opStroff(ea_t addr, string type) {
    insn_t insn;
    decode_insn(&insn, addr);
    tid_t struc_id = get_struc_id(type.c_str());
    return op_stroff(insn, 0, &struc_id, 1, 0);
}

//--------------------------------------------------------------------------
// Get pointer to named type and apply it
bool setPtrType(ea_t addr, string type) {
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
void setPtrTypeAndName(ea_t ea, string name, string type) {
    set_name(ea, name.c_str(), SN_CHECK);
    setPtrType(ea, type.c_str());
}

//--------------------------------------------------------------------------
// Check for guids.json file exist
bool guidsJsonExists() {
    /* get guids.json path */
    path guidsJsonPath;
    guidsJsonPath /= idadir("plugins");
    guidsJsonPath /= "guids";
    guidsJsonPath /= "guids.json";
    return std::filesystem::exists(guidsJsonPath);
}

//--------------------------------------------------------------------------
// Get json summary file name
path getSummaryFile() {
    string idbPath;
    idbPath = get_path(PATH_TYPE_IDB);
    path logFile;
    logFile /= idbPath;
    logFile.replace_extension(".json");
    return logFile;
}

//--------------------------------------------------------------------------
// Check for summary json file exist
bool summaryJsonExist() {
    string idbPath;
    idbPath = get_path(PATH_TYPE_IDB);
    path logFile;
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
            DEBUG_MSG("[%s] guess_tinfo failed, start_ea = 0x%016X, idx=%d\n",
                      plugin_name, start_ea, idx);
            continue;
        }
        func_type_data_t funcdata;
        if (!tif_ea.get_func_details(&funcdata)) {
            DEBUG_MSG("[%s] get_func_details failed, %d\n", plugin_name, idx);
            continue;
        }
        tinfo_t tif_pei;
        bool res = tif_pei.get_named_type(get_idati(), "EFI_PEI_SERVICES");
        if (!res) {
            DEBUG_MSG("[%s] get_named_type failed, res = %d, idx=%d\n",
                      plugin_name, res, idx);
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
                DEBUG_MSG("[%s] create_func failed, idx=%d\n", plugin_name,
                          idx);
                continue;
            }
            if (!apply_tinfo(start_ea, func_tinfo, TINFO_DEFINITE)) {
                DEBUG_MSG("[%s] get_named_type failed, idx=%d\n", plugin_name,
                          idx);
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
// Print vector<json> object
void printVectorJson(vector<json> in) {
    for (vector<json>::iterator item = in.begin(); item != in.end(); ++item) {
        json currentJson = *item;
        string s = currentJson.dump();
        DEBUG_MSG("[%s] %s\n", plugin_name, s.c_str());
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
// Collect information for dependency browser and dependency graph
vector<json> getDependenciesLoader() {
    vector<json> depJson;

    /* read summary and get allProtocols (also can be taken from memory) */
    path logFile = getSummaryFile();
    std::ifstream in(logFile);
    json summary;
    in >> summary;
    vector<json> allProtocols = summary["protocols"];

    /* get depJson */
    vector<string> locate{"LocateProtocol", "OpenProtocol"};
    vector<string> install{"InstallProtocolInterface",
                           "InstallMultipleProtocolInterfaces"};
    for (vector<json>::iterator protocolItem = allProtocols.begin();
         protocolItem != allProtocols.end(); ++protocolItem) {
        json protocol = *protocolItem;
        string service = static_cast<string>(protocol["service"]);
        if (find(install.begin(), install.end(), service) == install.end()) {
            continue;
        }
        /* get module name by address */
        ea_t address = static_cast<ea_t>(protocol["xref"]);
        qstring module_name = getModuleNameLoader(address);
        /* get depJsonItem */
        json depJsonItem;
        depJsonItem["module_name"] = static_cast<string>(module_name.c_str());
        depJsonItem["protocol_name"] = protocol["prot_name"];
        depJsonItem["guid"] = protocol["guid"];
        depJsonItem["service"] = protocol["service"];
        vector<string> used_by;
        for (vector<json>::iterator protocolItem = allProtocols.begin();
             protocolItem != allProtocols.end(); ++protocolItem) {
            json protocol = *protocolItem;
            string service = static_cast<string>(protocol["service"]);
            if (find(locate.begin(), locate.end(), service) == locate.end()) {
                continue;
            }
            if (depJsonItem["guid"] == protocol["guid"]) {
                address = static_cast<ea_t>(protocol["xref"]);
                qstring module_name = getModuleNameLoader(address);
                string mod_name(module_name.c_str());
                used_by.push_back(mod_name);
            }
        }
        depJsonItem["used_by"] = used_by;
        depJson.push_back(depJsonItem);
    }
    return depJson;
}

//--------------------------------------------------------------------------
// Get name for each node
vector<string> getNodes(vector<json> depJson) {
    vector<string> nodes;
    for (vector<json>::iterator depItem = depJson.begin();
         depItem != depJson.end(); ++depItem) {
        json dep = *depItem;
        string name = static_cast<string>(dep["module_name"]);
        if (find(nodes.begin(), nodes.end(), name) == nodes.end()) {
            nodes.push_back(name);
        }
        size_t len = dep["used_by"].size();
        for (auto i = 0; i < len; i++) {
            string name = static_cast<string>(dep["used_by"][i]);
            if (find(nodes.begin(), nodes.end(), name) == nodes.end()) {
                nodes.push_back(name);
            }
        }
    }
    return nodes;
}

//--------------------------------------------------------------------------
// Get edges
vector<json> getEdges(vector<string> depNodes, vector<json> depJson) {
    vector<json> edges;
    for (vector<json>::iterator depItem = depJson.begin();
         depItem != depJson.end(); ++depItem) {
        json dep = *depItem;
        size_t len = dep["used_by"].size();
        if (!len)
            continue;
        string nodeFrom = static_cast<string>(dep["module_name"]);
        for (auto i = 0; i < len; i++) {
            string nodeTo = static_cast<string>(dep["used_by"][i]);
            /* get node id for nodeFrom and nodeTo */
            auto nodeFromId = -1;
            auto nodeToId = -1;
            for (auto n = 0; n < depNodes.size(); n++) {
                if (depNodes[n] == nodeFrom)
                    nodeFromId = n;
                if (depNodes[n] == nodeTo)
                    nodeToId = n;
                if (nodeFromId >= 0 && nodeToId >= 0)
                    break;
            }
            if (nodeFromId < 0 || nodeToId < 0)
                continue;
            json edge;
            edge["from"] = nodeFromId;
            edge["to"] = nodeToId;
            edges.push_back(edge);
        }
    }
    return edges;
}
