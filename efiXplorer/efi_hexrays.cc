/*
 * efiXplorer
 * Copyright (C) 2020-2024 Binarly, Rolf Rolles
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
 */

#include "efi_hexrays.h"

// given a tinfo_t specifying a user-defined type (UDT), look up the specified
// field by its name, and retrieve its offset.
bool offset_of(tinfo_t tif, const char *name, unsigned int *offset) {
  // get the udt details
  udt_type_data_t udt;
  if (!tif.get_udt_details(&udt)) {
    qstring str;
    tif.get_type_name(&str);
    return false;
  }

  // find the udt member
#if IDA_SDK_VERSION < 840
  udt_member_t udm;
  udm.name = name;
  int fIdx = tif.find_udt_member(&udm, STRMEM_NAME);
#else
  udm_t udm;
  udm.name = name;
  int fIdx = tif.find_udm(&udm, STRMEM_NAME);
#endif
  if (fIdx < 0) {
    qstring tstr;
    tif.get_type_name(&tstr);
    return false;
  }

  // get the offset of the field
  *offset = static_cast<unsigned int>(udt.at(fIdx).offset >> 3ULL);
  return true;
}

// Utility function to set a Hex-Rays variable type and set types for the
// interfaces
bool set_hexrays_var_info_and_handle_interfaces(ea_t func_addr, lvar_t &ll,
                                                tinfo_t tif, std::string name) {
  lvar_saved_info_t lsi;
  lsi.ll = ll;
  lsi.type = tif;
  modify_user_lvar_info(func_addr, MLI_TYPE, lsi);

  // Set lvar name
  if (ll.is_stk_var()) { // Rename local variable on stack
#if IDA_SDK_VERSION < 900
    sval_t stkoff = ll.get_stkoff();
    struc_t *frame = get_frame(func_addr);
    set_member_name(frame, stkoff, name.c_str());
#endif     // TODO(yeggor): add support for idasdk90
  } else { // Modufy user lvar info
    lsi.name = static_cast<qstring>(name.c_str());
    modify_user_lvar_info(func_addr, MLI_NAME, lsi);
  }

  // Get xrefs to local variable
  xreflist_t xrefs = efi_utils::xrefs_to_stack_var(
      func_addr, static_cast<qstring>(name.c_str()));
  qstring type_name;
  ptr_type_data_t pi;
  tif.get_ptr_details(&pi);
  pi.obj_type.get_type_name(&type_name);
  // Handling all interface functions (to rename function arguments)
  efi_utils::op_stroff_for_interface(xrefs, type_name);

  return true;
}

// Utility function to set a Hex-Rays variable name
bool set_lvar_name(qstring name, lvar_t lvar, ea_t func_addr) {
  lvar_saved_info_t lsi;
  lvar_uservec_t lvuv;

  lsi.ll = lvar;
  lsi.name = name;
  if (!lvuv.lvvec.add_unique(lsi)) {
    return false;
  }
  save_user_lvar_settings(func_addr, lvuv);
  return true;
}

// Utility function to set a Hex-Rays variable type and name
bool set_hexrays_var_info(ea_t func_addr, lvar_t &ll, tinfo_t tif,
                          std::string name) {
  lvar_saved_info_t lsi;
  lsi.ll = ll;
  lsi.type = tif;
  modify_user_lvar_info(func_addr, MLI_TYPE, lsi);

  // Set lvar name
  if (ll.is_stk_var()) { // Rename local variable on stack
#if IDA_SDK_VERSION < 900
    sval_t stkoff = ll.get_stkoff();
    struc_t *frame = get_frame(func_addr);
    set_member_name(frame, stkoff, name.c_str());
#endif     // TODO(yeggor): add support for idasdk90
  } else { // Modufy user lvar info
    lsi.name = static_cast<qstring>(name.c_str());
    modify_user_lvar_info(func_addr, MLI_NAME, lsi);
  }

  return true;
}

// I added this bit of logic when I noticed that sometimes Hex-Rays will
// aggressively create arrays on the stack. So, I wanted to apply types to
// stack "variables" (whose pointers are passed to the protocol location
// functions), but according to Hex-Rays, they weren't "variables", they
// were arrays. This bit of logic generically detects arrays of either POD
// types, or perhaps pointers to POD types. The final argument allows the
// caller to specify the maximum depth "depth" of the pointers. E.g. at
// depth 1, "int *[10]" is acceptable. At depth 2, "int **[10]" is acceptable.
bool is_pod_array(tinfo_t tif, unsigned int ptrDepth = 0) {
  // If it's not an array, we're done
  if (!tif.is_array())
    return false;

  qstring tstr;

  // If it is an array, we should be able to get its array details.
  array_type_data_t atd;
  if (!tif.get_array_details(&atd)) {
    tif.get_type_name(&tstr);
    return false;
  }

  // Get the element type from the array
  tinfo_t et = atd.elem_type;

  // Start off with depth + 1, so the loop will execute at least once
  int iDepth = ptrDepth + 1;

  // Loop over the user-specified depth
  while (iDepth > 0) {
    // Use typeid last checks. I should clean this up; I'm sure I can get rid
    // of one of them.
    bool b1 = is_typeid_last(et.get_realtype());
    bool b2 = et.is_decl_last();

    // Debug printing
    et.get_type_name(&tstr);

    // If it was an integer type, return true
    if (b1 || b2)
      return true;

    // Otherwise, this is where the "pointer depth" comes in.
    // If we haven't exhausted the pointer depth,
    if (--iDepth > 0) {
      // Remove one layer of indirection from the element type
      if (et.is_ptr())
        et = remove_pointer(et);

      // Unless it's not a pointer, then return false.
      else
        return false;
    }
  }

  // If the array wasn't pointers of POD types up to the specified depth, we
  // failed. Return false.
  return false;
}

// Utility function to get a printable qstring from a cexpr_t
const char *expr_to_string(cexpr_t *e, qstring *out) {
  e->print1(out, nullptr);
  tag_remove(out);
  return out->c_str();
}

bool apply_all_types_for_interfaces(json_list_t protocols) {
  if (!init_hexrays_plugin()) {
    return false;
  }

  // Descriptors for EFI_BOOT_SERVICES functions
  struct TargetFunctionPointer BootServicesFunctions[5]{
      {"InstallProtocolInterface", 0x80, 4, 1, 3},
      {"HandleProtocol", 0x98, 3, 1, 2},
      {"OpenProtocol", 0x118, 6, 1, 2},
      {"LocateProtocol", 0x140, 3, 0, 2},
      {"InstallMultipleProtocolInterfaces", 0x148, 4, 1, 2}};

  // Initialize
  ServiceDescriptor sdBs;
  sdBs.Initialize("EFI_BOOT_SERVICES", BootServicesFunctions, 5);

  ServiceDescriptorMap mBs;
  mBs.Register(sdBs);

  GUIDRetyper retyperBs(mBs);
  retyperBs.SetProtocols(protocols);

  // Handle all protocols
  for (auto protocol : protocols) {
    auto code_addr = protocol["ea"];
    auto service = protocol["service"];

    func_t *f = get_func(code_addr);
    if (f == nullptr) {
      continue;
    }

    retyperBs.SetCodeEa(code_addr);
    retyperBs.SetFuncEa(f->start_ea);

    hexrays_failure_t hf;
    cfuncptr_t cfunc = decompile(f, &hf, DECOMP_NO_WAIT);

    // Сheck that the function is decompiled
    if (cfunc == nullptr) {
      continue;
    }

    retyperBs.apply_to(&cfunc->body, nullptr);
  }

  return true;
}

bool apply_all_types_for_interfaces_smm(json_list_t protocols) {
  if (!init_hexrays_plugin()) {
    return false;
  }

  // Descriptors for _EFI_SMM_SYSTEM_TABLE2 functions
  struct TargetFunctionPointer SmmServicesFunctions[2]{
      {"SmmHandleProtocol", 0xb8, 3, 1, 2},
      {"SmmLocateProtocol", 0xd0, 3, 0, 2},
  };

  // Initialize
  ServiceDescriptor sdSmm;
  sdSmm.Initialize("_EFI_SMM_SYSTEM_TABLE2", SmmServicesFunctions, 2);

  ServiceDescriptorMap mSmm;
  mSmm.Register(sdSmm);

  GUIDRetyper retyperSmm(mSmm);
  retyperSmm.SetProtocols(protocols);

  // Handle all protocols
  for (auto protocol : protocols) {
    auto code_addr = protocol["ea"];
    auto service = protocol["service"];

    func_t *f = get_func(code_addr);
    if (f == nullptr) {
      continue;
    }

    retyperSmm.SetCodeEa(code_addr);
    retyperSmm.SetFuncEa(f->start_ea);

    hexrays_failure_t hf;
    cfuncptr_t cfunc = decompile(f, &hf, DECOMP_NO_WAIT);

    // Сheck that the function is decompiled
    if (cfunc == nullptr) {
      continue;
    }

    retyperSmm.apply_to(&cfunc->body, nullptr);
  }

  return true;
}

uint8_t variables_info_extract_all(func_t *f, ea_t code_addr) {
  if (!init_hexrays_plugin()) {
    return 0xff;
  }

  // check func
  if (f == nullptr) {
    return 0xff;
  }
  VariablesInfoExtractor extractor(code_addr);
  hexrays_failure_t hf;
  cfuncptr_t cfunc = decompile(f, &hf, DECOMP_NO_WAIT);
  // Сheck that the function is decompiled
  if (cfunc == nullptr) {
    return 0xff;
  }
  extractor.apply_to(&cfunc->body, nullptr);
  auto res = extractor.mAttributes;
  return res;
}

bool track_entry_params(func_t *f, uint8_t depth) {
  if (!init_hexrays_plugin()) {
    return false;
  }

  if (depth == 2) {
    return true;
  }

  if (f == nullptr) {
    return false;
  }

  hexrays_failure_t hf;
  cfuncptr_t cfunc = decompile(f, &hf, DECOMP_NO_WAIT);
  if (cfunc == nullptr) {
    return false;
  }

  PrototypesFixer *pf = new PrototypesFixer();
  pf->apply_to(&cfunc->body, nullptr);
  for (auto addr : pf->child_functions) {
    track_entry_params(get_func(addr), ++depth);
  }

  delete pf;

  return true;
}

json detect_vars(func_t *f) {
  json res;

  if (!init_hexrays_plugin()) {
    return res;
  }

  // check func
  if (f == nullptr) {
    return res;
  }
  VariablesDetector vars_detector;
  hexrays_failure_t hf;
  cfuncptr_t cfunc = decompile(f, &hf, DECOMP_NO_WAIT);
  if (cfunc == nullptr) {
    return res;
  }

  vars_detector.SetFuncEa(f->start_ea);
  vars_detector.apply_to(&cfunc->body, nullptr);

  res["image_handle_list"] = vars_detector.image_handle_list;
  res["st_list"] = vars_detector.st_list;
  res["bs_list"] = vars_detector.bs_list;
  res["rt_list"] = vars_detector.rt_list;

  return res;
}

json_list_t detect_services(func_t *f) {
  // check func
  json_list_t res;

  if (!init_hexrays_plugin()) {
    return res;
  }

  if (f == nullptr) {
    return res;
  }
  ServicesDetector services_detector;
  hexrays_failure_t hf;
  cfuncptr_t cfunc = decompile(f, &hf, DECOMP_NO_WAIT);
  if (cfunc == nullptr) {
    return res;
  }
  services_detector.apply_to(&cfunc->body, nullptr);
  return services_detector.services;
}

bool detect_pei_services(func_t *f) {
  if (!init_hexrays_plugin()) {
    return false;
  }

  if (f == nullptr) {
    return false;
  }

  PeiServicesDetector pei_services_detector;
  hexrays_failure_t hf;
  cfuncptr_t cfunc = decompile(f, &hf, DECOMP_NO_WAIT);
  if (cfunc == nullptr) {
    return false;
  }
  pei_services_detector.apply_to(&cfunc->body, nullptr);

  return true;
}

json_list_t detect_pei_services_arm(func_t *f) {
  json_list_t res;

  if (!init_hexrays_plugin()) {
    return res;
  }

  if (f == nullptr) {
    return res;
  }

  PeiServicesDetectorArm pei_services_detector_arm;
  hexrays_failure_t hf;
  cfuncptr_t cfunc = decompile(f, &hf, DECOMP_NO_WAIT);
  if (cfunc == nullptr) {
    return res;
  }
  pei_services_detector_arm.apply_to(&cfunc->body, nullptr);
  return pei_services_detector_arm.services;
}
