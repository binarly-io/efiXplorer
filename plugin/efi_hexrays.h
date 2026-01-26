// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2020-2026 Binarly

#pragma once

#include "efi_utils.h"
#include "pro.h"
#include <map>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace efi_hexrays {
bool apply_all_types_for_interfaces_smm(json_list_t guids);
bool apply_all_types_for_interfaces(json_list_t guids);
bool detect_pei_services(func_t *f);
bool is_pod_array(tinfo_t tif, unsigned int ptr_depth);
bool offset_of(tinfo_t tif, const char *name, unsigned int *offset);
bool set_hexrays_var_info_and_handle_interfaces(ea_t func_addr, lvar_t &ll,
                                                tinfo_t tif, std::string name);
bool set_hexrays_var_info(ea_t func_addr, lvar_t &ll, tinfo_t tif,
                          std::string name);
bool set_lvar_name(qstring name, lvar_t &lvar, ea_t func_addr);
bool propagate_types(func_t *f, uint8_t depth);
const char *expr_to_string(cexpr_t *e, qstring *out);
json detect_vars(func_t *f);
json_list_t detect_pei_services_arm(func_t *f);
json_list_t detect_services(func_t *f);
uint8_t variables_info_extract_all(func_t *f, ea_t code_addr);
xreflist_t xrefs_to_stack_var(ea_t func_addr, lvar_t &ll, qstring name);

// description of a function pointer within a structure. Ultimately, this
// plugin is looking for calls to specific UEFI functions. This structure
// describes basic information about those functions:
struct target_funcptr_t {
  const char *name;      // name of function pointer in structure
  int offset;            // offset of function pointer (filled in later)
  unsigned int args;     // number of expected arguments
  unsigned int guid_arg; // which argument has the EFI_GUID *
  unsigned int out_arg;  // which argument retrieves the output
};

// this class holds all function pointer descriptors for one structure, as well
// as providing a utility to look up function pointers by offset
class service_descriptor_t {
  // instance data
protected:
  // the type of the containing structure (e.g. EFI_BOOT_SERVICES)
  tinfo_t m_type;

  // the name of the type (e.g. "EFI_BOOT_SERVICES")
  qstring m_name;

  // the ordinal of the type (e.g. 4)
  uint32 m_ordinal;

  // a vector of the structures above, copied, and with the offsets filled in
  std::vector<target_funcptr_t> m_targets;

  bool b_initialised;

  // ensure we can look up the type that this instance describes
  bool init_type(const char *name) {
    // import type
    import_type(get_idati(), -1, name);

    // get type by name
    if (!m_type.get_named_type(get_idati(), name))
      return false;

    // save ordinal and name
    m_ordinal = m_type.get_ordinal();
    m_name = name;
    return true;
  }

  // look up the offsets for all function pointer targets; save the results
  // in the vector; return false if offset lookup fails
  bool init_targets(target_funcptr_t *targets, size_t num) {
    // iterate through all targets
    for (int i = 0; i < num; ++i) {
      // copy the target structure into our local vector
      target_funcptr_t &tgt = m_targets.emplace_back();
      tgt = targets[i];

      // retrieve the offsets of each named function pointer
      unsigned int offset;
      if (!offset_of(m_type, targets[i].name, &offset)) {
        return false;
      }
    }
    return true;
  }

public:
  // constructor does nothing
  service_descriptor_t() : m_ordinal(0), b_initialised(false) {}

  // accessor for ordinal
  uint32 get_ordinal() { return m_ordinal; }

  // accessor for name
  const char *get_name() { return m_name.c_str(); }

  // needs to be called before the object can be used
  bool initialise(const char *name, target_funcptr_t *targets, size_t num) {
    if (b_initialised)
      return true;
    b_initialised = init_type(name) && init_targets(targets, num);
    return b_initialised;
  }

  // after initialisation, look up a target by offset
  bool lookup_offset(unsigned int offset, target_funcptr_t **tgt) {
    // iterating through a vector generally is inefficient compared
    // to a map, but there are at most 3 function pointers so far, so it
    // outweighs the overhead of the associative containers.
    for (auto &it : m_targets) {
      // Match by offset
      if (it.offset == offset) {
        *tgt = &it;
        return true;
      }
    }
    // if we don't find it, it's not necessarily "bad" from the
    // point of view of the plugin's logic. After all, we're looking at every
    // access to the selected structures, and so, quite rightly, we'll want to
    // ignore the function pointers that we're not tracking.
    return false;
  }
};

// this class manages multiple instances of the class above. Each
// such structure is associated with the ordinal of its containing structure
// type. Then, when the Hex-Rays visitor needs to look up a function pointer
// access into a structure, it just passes the structure ordinal and offset.
// This class looks up the service_descriptor_t in a map by ordinal, and then
// looks up the offset if that succeeded.
class service_descriptor_map_t {
protected:
  // our map for looking up service_descriptor_t structures. I
  // should probably change the value type to a pointer.
  std::map<uint32, service_descriptor_t> m_services;

public:
  // add a new service_descriptor_t to the map. I should change the
  // argument type to match whatever I change the value type of the map to.
  bool register_sd(service_descriptor_t sd) {
    // get the ordinal from the service_descriptor_t
    uint32 ord = sd.get_ordinal();

    // are we already tracking this structure?
    if (m_services.find(ord) != m_services.end()) {
      return false;
    }
    // if not, register it. Get rid of std::move
    m_services[ord] = std::move(sd);
    return true;
  }

  // this function could be protected, but whatever. Given an ordinal, get
  // the tracked service_descriptor_t, if applicable
  bool lookup_ordinal(uint32 ord, service_descriptor_t **sd) {
    auto it = m_services.find(ord);
    if (it == m_services.end()) {
      return false;
    }
    *sd = &it->second;
    return true;
  }

  // this is the high-level function that clients call. Given a structure
  // ordinal and offset of a function pointer, see if it's something we're
  // tracking. If so, get pointers to the tracked objects and return true.
  bool lookup_offset(uint32 ord, unsigned int offset, service_descriptor_t **sd,
                     target_funcptr_t **tgt) {
    if (!lookup_ordinal(ord, sd))
      return false;
    if (!(*sd)->lookup_offset(offset, tgt))
      return false;
    return true;
  }
};

// base class for two visitors that require similar functionality. Here we
// collect all of the common data and functionality that will be used by both
// of those visitors. This allows the derivatives to be very succinct.
class guid_related_visitor_base_t : public ctree_visitor_t {
public:
  // we need access to a service_descriptor_map_t from above
  explicit guid_related_visitor_base_t(service_descriptor_map_t &m)
      : ctree_visitor_t(CV_FAST), m_debug(true), m_services(m) {}

  // we need the function ea when setting Hex-Rays variable types
  void set_func_ea(ea_t ea) { m_func_ea = ea; }
  void set_code_ea(ea_t ea) { m_code_ea = ea; }
  void set_protocols(json_list_t protocols) { m_protocols = protocols; }

protected:
  ea_t m_func_ea;
  ea_t m_code_ea;
  json_list_t m_protocols;
  bool m_debug = true;

  // used for looking up calls to function pointers in structures
  service_descriptor_map_t &m_services;

  //
  // state variables, cleared on every iteration. I debated with myself
  // whether this was a nasty design decision. I think it's fine. These
  // variables are only valid to access after the client has called
  // validate_call_and_guid, and it returned true. If you called that and it
  // returned false, these will be in an inconsistent state. Don't touch them
  // if that's the case.
  //

  // address of the indirect function call
  ea_t m_ea;

  // the pointer type that's being accessed (that of the structure)
  tinfo_t m_tif;

  // the structure type, with the pointer indirection removed
  tinfo_t m_tif_noptr;

  // the service_descriptor_t for the containing structure
  service_descriptor_t *m_service;

  // the ordinal of the structure type
  uint32 m_ordinal;

  // the offset of the function pointer in the structure
  unsigned int m_offset;

  // details about the target of the indirect call (e.g. name)
  target_funcptr_t *m_target;

  // the list of arguments for the indirect call
  carglist_t *m_args;

  // the argument that specifies the GUID for the indirect call
  cexpr_t *m_guid_arg;

  // the argument that gets the output for the indirect call
  cexpr_t *m_out_arg;

  // the GUID argument will be &x; this is x
  cexpr_t *m_guid_arg_ref_to;

  // the address of the GUID being passed to the indirect call
  ea_t m_guid_ea;

  void clear() {
    m_ea = BADADDR;
    m_tif.clear();
    m_tif_noptr.clear();
    m_service = nullptr;
    m_ordinal = 0;
    m_offset = -1;
    m_target = nullptr;
    m_args = nullptr;
    m_guid_arg = nullptr;
    m_out_arg = nullptr;
    m_guid_arg_ref_to = nullptr;
    m_guid_ea = BADADDR;
  }

  // this is the first function called every time the visitor visits an
  // expression. This function determines if the expression is a call to a
  // function pointer contained in a structure
  bool get_call_ord_and_offset(cexpr_t *e) {
    // set instance variable for call address
    m_ea = e->ea;

    if (m_ea != m_code_ea) {
      return false;
    }

    // if it's not a call, we're done
    if (e->op != cot_call)
      return false;

    // set instance variable with call arguments
    m_args = e->a;

    // if it's a direct call, we're done
    cexpr_t *call_dest = e->x;
    if (call_dest->op == cot_obj)
      return false;

    // eat any casts on the type of what's being called
    while (call_dest->op == cot_cast)
      call_dest = call_dest->x;

    // if the destination is not a member of a structure, we're done
    if (call_dest->op != cot_memptr)
      return false;

    // set instance variable with type of structure containing pointer
    m_tif = call_dest->x->type;

    // ensure that the structure is being accessed via pointer, and not as a
    // reference (i.e., through a structure held on the stack as a local
    // variable)
    if (!m_tif.is_ptr()) {
      return false;
    }

    // remove pointer from containing structure type, set instance variable
    m_tif_noptr = remove_pointer(m_tif);

    // get the ordinal of the structure
    m_ordinal = m_tif_noptr.get_ordinal();

    // if we can't get a type for the structure, that's bad
    if (m_ordinal == 0)
      return false;

    // get the offset of the function pointer in the structure
    m_offset = call_dest->m;

    // now we know we're dealing with an indirect call to a function
    // pointer contained in a structure, where the structure is being
    // accessed by a pointer
    return true;
  }

  // this is the second function called as part of indirect call validation.
  // Now we want to know: is it a call to something that we're tracking?
  bool validate_call_destination() {
    // look up the structure ordinal and function offset; get the associated
    // service_descriptor_t and target_funcptr_t (instance variables)
    if (!m_services.lookup_offset(m_ordinal, m_offset, &m_service, &m_target))
      return false;

    // it was something that we were tracking. Now, sanity-check the
    // number of arguments on the function call. (Hex-Rays might have gotten
    // this wrong. The user can fix it via "set call type")
    size_t args_size = m_args->size();
    size_t args = m_target->args;
    if (args_size != args) {
      return false;
    }

    // the target_funcptr_t tells us which argument takes an EFI_GUID *,
    // and which one retrieves the output. Get those arguments, and save them
    // as instance variables
    m_guid_arg = &m_args->at(m_target->guid_arg);
    m_out_arg = &m_args->at(m_target->out_arg);

    // now we know that the expression is an indirect call to
    // something that we're tracking, and that Hex-Rays decompiled the call
    // the way we expected it to
    return true;
  }

  // this is a helper function used to get the thing being referred to. What
  // does that m_ean?
  //
  // - for GUID arguments, we'll usually have &globvar. Return globvar
  // - for output arguments, we'll usually have &globvar or &locvar. Due to
  //   Hex-Rays internal heuristics, we might end up with "locarray", which
  //   does not actually have a "&" when passed as a call argument. There's
  //   a bit of extra logic to check for that case
  cexpr_t *get_referent(cexpr_t *e, const char *desc, bool b_accept_var) {
    // Eat casts
    cexpr_t *x = e;
    while (x->op == cot_cast)
      x = x->x;

    qstring estr;
    // if we're accepting local variables, and this is a variable (note: not
    // a *reference* to a variable)
    if (b_accept_var && x->op == cot_var) {
      // get the variable details
      var_ref_t var_ref = x->v;
      lvar_t dest_var = var_ref.mba->vars[var_ref.idx];

      // ensure that it's an array of POD types, or pointers to them
      bool bis_pod_array = is_pod_array(dest_var.tif, 1);

      // if it is a POD array, good, we'll take it
      return bis_pod_array ? x : nullptr;
    }

    // for everything else, we really want it to be a reference: either to a
    // global or local variable. If it's not a reference, we can't get the
    // referent, so fail
    if (x->op != cot_ref) {
      return nullptr;
    }

    // if we get here, we know it's a reference. Return the referent.
    return x->x;
  }

  // the third function in the validation logic. We already know the
  // expression is an indirect call to something that we're tracking, and
  // that Hex-Rays' decompilation matches on the number of arguments. Now,
  // we validate that the GUID argument does in fact point to a global
  // variable
  bool validate_guid_arg() {
    // does the GUID argument point to a local variable?
    m_guid_arg_ref_to = get_referent(m_guid_arg, "GUID", false);
    if (!m_guid_arg_ref_to)
      return false;

    // if we get here, we know it was a reference to *something*. Ensure that
    // something is a global variable
    if (m_guid_arg_ref_to->op != cot_obj) {
      return false;
    }

    // save the address of the global variable to which the GUID argument is
    // pointing
    m_guid_ea = m_guid_arg_ref_to->obj_ea;

    // now we know we're dealing with an indirect call to something
    // we're tracking; that Hex-Rays decompiled the call with the proper
    // number of arguments; and that the GUID argument did in fact point to
    // a global variable, whose address we now have in an instance variable.
    return true;
  }

  // finally, this function combines all three checks above into one single
  // function. If you call this and it returns true, feel free to access the
  // instance variables, as they are guaranteed to be valid. If it returns
  // false, they aren't, so don't touch them
  bool validate_call_and_guid(cexpr_t *e) {
    // Reset all instance variables. Not strictly necessary; call it
    // "defensive programming".
    clear();

    // validate according to the logic above
    return (get_call_ord_and_offset(e) && validate_call_destination() &&
            validate_guid_arg());
  }
};

// now that we've implemented all that validation logic, this class is pretty
// simple. This one is responsible for ensuring that the GUID is something that
// we know about, and setting the types of the output variables accordingly
class guid_retyper_t : public guid_related_visitor_base_t {
public:
  explicit guid_retyper_t(service_descriptor_map_t &m)
      : guid_related_visitor_base_t(m), m_num_applied(0) {}

  // this is the callback function that Hex-Rays invokes for every expression
  // in the CTREE
  int visit_expr(cexpr_t *e) {
    // perform the checks from guid_related_visitor_base_t. If they fail, we're
    // not equipped to deal with this expression, so bail out
    if (!validate_call_and_guid(e))
      return 0;

    m_guid_arg_ref_to = get_referent(m_guid_arg, "GUID", false);
    if (m_guid_arg_ref_to == nullptr)
      return 0;
    ea_t guidAddr = m_guid_arg_ref_to->obj_ea;

    // get interface type name
    std::string guid_name;
    for (auto g : m_protocols) {
      if (guidAddr == g["address"]) {
        guid_name = g["prot_name"];
        break;
      }
    }
    if (guid_name.empty()) {
      return 0;
    }

    std::string interface_type_name =
        guid_name.substr(0, guid_name.find("_GUID"));
    if (!interface_type_name.find("FCH_")) {
      // convert FCH_SMM_* dispatcher type to EFI_SMM_* dispatcher type
      interface_type_name.replace(0, 4, "EFI_");
    }

    // need to get the type for the interface variable here
    tinfo_t tif;
    import_type(get_idati(), -1, interface_type_name.c_str());
    if (!tif.get_named_type(get_idati(), interface_type_name.c_str())) {
      // get the referent for the interface argument
      cexpr_t *out_arg_referent = get_referent(m_out_arg, "ptr", true);
      if (out_arg_referent == nullptr)
        return 0;
      apply_name(out_arg_referent, interface_type_name);
      return 0;
    }

    qstring tstr;
    if (!tif.get_type_name(&tstr)) {
      return 0;
    }

    tinfo_t tif_guid_ptr;
    if (!tif_guid_ptr.create_ptr(tif)) {
      return 0;
    }

    // get the referent for the interface argument
    cexpr_t *out_arg_referent = get_referent(m_out_arg, "ptr", true);
    if (out_arg_referent == nullptr)
      return 0;

    // apply the type to the output referent
    apply_type(out_arg_referent, tif_guid_ptr, tstr);
    return 1;
  }

protected:
  unsigned int m_num_applied;

  // given an expression (either a local or global variable) and a type to
  // apply, apply the type. This is just a bit of IDA/Hex-Rays type system
  // skullduggery
  void apply_type(cexpr_t *out_arg, tinfo_t ptr_tif, qstring tstr) {
    ea_t dest_ea = out_arg->obj_ea;

    // for global variables
    if (out_arg->op == cot_obj) {
      // just apply the type information to the address
      apply_tinfo(dest_ea, ptr_tif, TINFO_DEFINITE);
      ++m_num_applied;

      // rename global variable
      auto name = "g" + efi_utils::type_to_name(tstr.c_str());
      set_name(dest_ea, name.c_str(), SN_FORCE);

      // get xrefs to global variable
      auto xrefs = efi_utils::get_xrefs(dest_ea);
      qstring type_name;
      ptr_type_data_t pi;
      ptr_tif.get_ptr_details(&pi);
      pi.obj_type.get_type_name(&type_name);

      // handling all interface functions (to rename function arguments)
      efi_utils::op_stroff_for_global_interface(xrefs, type_name);
    } else if (out_arg->op == cot_var) { // for local variables
      var_ref_t var_ref = out_arg->v;
      lvar_t &dest_var = var_ref.mba->vars[var_ref.idx];

      // set the Hex-Rays variable type
      auto name = efi_utils::type_to_name(tstr.c_str());
      set_lvar_name(name.c_str(), dest_var, m_func_ea);
      if (set_hexrays_var_info_and_handle_interfaces(m_func_ea, dest_var,
                                                     ptr_tif, name)) {
        ++m_num_applied;
      }
    }
  }

  void apply_name(cexpr_t *out_arg, std::string type_name) {
    ea_t dest_ea = out_arg->obj_ea;

    // for global variables
    if (out_arg->op == cot_obj) {
      // rename global variable
      auto name = "g" + efi_utils::type_to_name(type_name);
      set_name(dest_ea, name.c_str(), SN_FORCE);
    } else if (out_arg->op == cot_var) { // for local variables
      var_ref_t var_ref = out_arg->v;
      lvar_t &dest_var = var_ref.mba->vars[var_ref.idx];
      // set the Hex-Rays variable type
      auto name = efi_utils::type_to_name(type_name);
      set_lvar_name(name.c_str(), dest_var, m_func_ea);
    }
  }
};

class variables_info_extractor_t : public ctree_visitor_t {
public:
  explicit variables_info_extractor_t(ea_t code_addr)
      : ctree_visitor_t(CV_FAST) {
    m_code_addr = code_addr;
  }

  uint8_t m_attributes = 0xff;

  // this is the callback function that Hex-Rays invokes for every expression
  // in the CTREE
  int visit_expr(cexpr_t *e) {
    if (m_code_addr == BADADDR) {
      return 0;
    }

    if (e->ea != m_code_addr) {
      return 0;
    }

    if (e->op != cot_call)
      return 0;

    carglist_t *args = e->a;
    if (args == nullptr) {
      return 0;
    }

    size_t args_size = args->size();
    if (args_size < 3) {
      return 0;
    }

    cexpr_t *attributes_arg = &args->at(2);
    if (attributes_arg->op == cot_num) {
      attributes_arg->numval();
      m_attributes = static_cast<uint8_t>(attributes_arg->numval());
    }

    return 0;
  }

protected:
  ea_t m_code_addr = BADADDR;
  bool m_debug = true;
};

class type_propagator_t : public ctree_visitor_t {
public:
  type_propagator_t() : ctree_visitor_t(CV_FAST) {}
  ea_set_t m_child_functions;

  // this is the callback function that Hex-Rays invokes for every expression
  // in the CTREE
  int visit_expr(cexpr_t *e) {
    if (e->op != cot_call) {
      return 0;
    }

    // get child function address
    if (e->x->op != cot_obj) {
      return 0;
    }

    if (m_debug) {
      efi_utils::log("child function address: 0x%" PRIx64 "\n",
                     u64_addr(e->x->obj_ea));
    }

    carglist_t *args = e->a;
    if (args == nullptr) {
      return 0;
    }

    // get child function prototype
    ea_t func_addr = e->x->obj_ea;
    hexrays_failure_t hf;
    func_t *f = get_func(func_addr);
    if (f == nullptr) {
      return 0;
    }

    cfuncptr_t cf = decompile(f, &hf, DECOMP_NO_WAIT);
    if (cf == nullptr) {
      return 0;
    }

    if (m_debug) {
      efi_utils::log("call address: 0x%" PRIx64 "\n", u64_addr(e->ea));
    }

    for (auto i = 0; i < args->size(); i++) {
      cexpr_t *arg = &args->at(i);
      if (arg->op == cot_cast || arg->op == cot_var) {
        // extract argument type
        tinfo_t arg_type;
        tinfo_t arg_type_no_ptr;
        if (arg->op == cot_var) {
          arg_type = arg->type;
        }

        if (arg->op == cot_cast) {
          arg_type = arg->x->type;
        }

        // print type
        if (arg_type.is_ptr()) {
          arg_type_no_ptr = remove_pointer(arg_type);
        }

        qstring type_name;
        bool is_ptr = !arg_type.get_type_name(&type_name);
        if (is_ptr && !arg_type_no_ptr.get_type_name(&type_name)) {
          continue;
        }

        if (is_ptr) {
          efi_utils::log("arg #%d, type = %s *\n", i, type_name.c_str());
        } else {
          efi_utils::log("arg #%d, type = %s\n", i, type_name.c_str());
        }

        auto it = m_names.find(type_name.c_str());
        if (it == m_names.end()) {
          continue;
        }

        m_child_functions.insert(func_addr);

        if (cf->argidx.size() <= i) {
          return 0;
        }

        auto argid = cf->argidx[i];
        lvar_t &arg_var = cf->mba->vars[argid]; // get lvar for argument
        set_hexrays_var_info(func_addr, arg_var, arg_type, it->second);
      }
    }

    return 0;
  }

protected:
  bool m_debug = true;
  static inline const std::unordered_map<std::string, const char *> m_names = {
      {"EFI_HANDLE", "ImageHandle"},
      {"EFI_SYSTEM_TABLE", "SystemTable"},
      {"EFI_SMM_SYSTEM_TABLE2", "Smst"},
  };
};

class variables_detector_t : public ctree_visitor_t {
public:
  variables_detector_t() : ctree_visitor_t(CV_FAST) {}

  ea_set_t m_child_functions;

  ea_set_t m_image_handle_list;
  ea_set_t m_st_list;
  ea_set_t m_bs_list;
  ea_set_t m_rt_list;

  void set_func_ea(ea_t ea) { m_func_ea = ea; }

  // this is the callback function that Hex-Rays invokes for every expression
  // in the CTREE
  int visit_expr(cexpr_t *e) {
    if (e->op == cot_asg) {
      // saving a child function for recursive analysis
      m_child_functions.insert(e->x->obj_ea);
    }

    bool global_var = false;
    bool local_var = false;
    if (e->op != cot_asg) {
      return 0;
    }

    switch (e->x->op) {
    case cot_obj:
      // asg operation for global variable
      global_var = true;
      break;
    case cot_var:
      // asg operation for local variable
      local_var = true;
      break;
    default:
      return 0;
    }

    // extract variable type
    tinfo_t var_type;
    tinfo_t var_type_no_ptr;
    if (e->y->op == cot_memptr && e->y->x->op == cot_var) {
      var_type = e->y->type;
    } else if (e->y->op == cot_var) {
      var_type = e->y->type;
    } else if (e->y->op == cot_cast) {
      var_type = e->y->x->type;
    } else {
      return 0;
    }

    if (var_type.is_ptr()) {
      var_type_no_ptr = remove_pointer(var_type);
    }

    qstring type_name;
    bool is_ptr = false;
    if (!var_type.get_type_name(&type_name)) {
      if (!var_type_no_ptr.get_type_name(&type_name)) {
        return 0;
      }
      is_ptr = true;
    }

    if (m_debug) {
      efi_utils::log("code address: 0x%" PRIx64 ", type name: %s\n",
                     u64_addr(e->ea), type_name.c_str());
    }

    if (global_var) {
      // extract variable data
      ea_t g_addr = e->x->obj_ea;
      std::string type_name_str = type_name.c_str();
      if (type_name == "EFI_HANDLE") {
        efi_utils::set_type_and_name(g_addr, "gImageHandle", type_name_str);
        m_image_handle_list.insert(g_addr);
      }
      if (type_name == "EFI_SYSTEM_TABLE") {
        efi_utils::set_ptr_type_and_name(g_addr, "gST", type_name_str);
        m_st_list.insert(g_addr);
      }
      if (type_name == "EFI_BOOT_SERVICES") {
        efi_utils::set_ptr_type_and_name(g_addr, "gBS", type_name_str);
        m_bs_list.insert(g_addr);
      }
      if (type_name == "EFI_RUNTIME_SERVICES") {
        efi_utils::set_ptr_type_and_name(g_addr, "gRT", type_name_str);
        m_rt_list.insert(g_addr);
      }
    }

    if (local_var) {
      // set the Hex-Rays variable type
      auto name = efi_utils::type_to_name(type_name.c_str());
      efi_utils::log("found %s at 0x%" PRIx64 " (function: 0x%" PRIx64 ")\n",
                     name.c_str(), u64_addr(e->ea), u64_addr(m_func_ea));
    }

    return 0;
  }

protected:
  bool m_debug = true;
  ea_t m_func_ea = BADADDR;
};

class services_detector_t : public ctree_visitor_t {
  // detect all services (Boot services, Runtime services, etc)
public:
  services_detector_t() : ctree_visitor_t(CV_FAST) {}

  json_list_t m_services;

  // this is the callback function that Hex-Rays invokes for every expression
  // in the CTREE
  int visit_expr(cexpr_t *e) {
    if (e->op != cot_call) {
      return 0;
    }

    if (e->x->op != cot_cast) {
      return 0;
    }

    // extract function type
    auto e_func = e->x->x;
    tinfo_t func_type;
    tinfo_t func_type_no_ptr;

    func_type = e_func->type;

    if (func_type.is_ptr()) {
      func_type_no_ptr = remove_pointer(func_type);
    }

    qstring type_name;
    bool is_ptr = false;
    if (!func_type.get_type_name(&type_name)) {
      if (!func_type_no_ptr.get_type_name(&type_name)) {
        return 0;
      }
      is_ptr = 0;
    }

    auto service_name = efi_utils::type_to_name(type_name.c_str());
    if (service_name.rfind("Efi", 0) == 0) {
      service_name = service_name.substr(3);
      if (service_name == "RaiseTpl") {
        service_name = "RaiseTPL";
      }
      if (service_name == "RestoreTpl") {
        service_name = "RestoreTPL";
      }
    }
    if (m_debug) {
      efi_utils::log("address: 0x%" PRIx64
                     ", service type: %s, service name: %s\n",
                     u64_addr(e->ea), type_name.c_str(), service_name.c_str());
    }

    json s;
    s["address"] = e->ea;
    s["service_name"] = service_name;
    s["table_name"] = efi_utils::get_table_name(service_name);

    if (!efi_utils::json_in_vec(m_services, s)) {
      m_services.push_back(s);
    }

    return 0;
  }

protected:
  bool m_debug = true;
};

class pei_services_detector_t : public ctree_visitor_t {
  // detect and mark all PEI services
public:
  pei_services_detector_t() : ctree_visitor_t(CV_FAST) {}

  bool make_shifted_ptr(tinfo_t outer, tinfo_t inner, int32 offset,
                        tinfo_t *shifted_tif) {
    ptr_type_data_t pi;
    pi.taptr_bits = TAPTR_SHIFTED;
    pi.delta = offset;
    pi.parent = outer;
    pi.obj_type = inner;
    shifted_tif->create_ptr(pi);
    return shifted_tif->is_correct();
  }

  bool set_var_type(ea_t func_ea, lvar_t lvar, tinfo_t tif) {
    lvar_saved_info_t lsi;
    lsi.ll = lvar;
    lsi.type = tif;
    return modify_user_lvar_info(func_ea, MLI_TYPE, lsi);
  }

  // this is the callback function that Hex-Rays invokes for every expression
  // in the CTREE
  int visit_expr(cexpr_t *e) {
    auto pointer_offset = BADADDR;
    auto service_offset = BADADDR;
    bool call = false;
    var_ref_t var_ref;
    if (e->op == cot_ptr && e->x->op == cot_cast && e->x->x->op == cot_add &&
        e->x->x->x->op == cot_ptr && e->x->x->x->x->op == cot_ptr &&
        e->x->x->x->x->x->op == cot_cast &&
        e->x->x->x->x->x->x->op == cot_sub &&
        e->x->x->x->x->x->x->x->op == cot_var &&
        e->x->x->x->x->x->x->y->op == cot_num && e->x->x->y->op == cot_num) {
      // (*ADJ(v2)->PeiServices)->GetHobList(
      // (const EFI_PEI_SERVICES**)ADJ(v2)->PeiServices, HobList);
      service_offset = e->x->x->y->numval();
      pointer_offset = e->x->x->x->x->x->x->y->numval();
      var_ref = e->x->x->x->x->x->x->x->v;
      call = true;
    } else if (e->op == cot_asg && e->x->op == cot_var && e->y->op == cot_ptr &&
               e->y->x->op == cot_cast && e->y->x->x->op == cot_sub &&
               e->y->x->x->x->op == cot_var && e->y->x->x->y->op == cot_num) {
      // __sidt(v6);
      // PeiServices = ADJ(v7)->PeiServices;
      pointer_offset = e->y->x->x->y->numval();
      var_ref = e->y->x->x->x->v;
    } else {
      return 0;
    }

    if (pointer_offset != 4) {
      return 0;
    }

    efi_utils::log("PEI service detected at 0x%" PRIx64 "\n", u64_addr(e->ea));

    tinfo_t outer;
    if (!outer.get_named_type(get_idati(), "EFI_PEI_SERVICES_4", BTF_STRUCT)) {
      return 0;
    }

    tinfo_t shifted_tif;
    if (!make_shifted_ptr(outer, outer, pointer_offset, &shifted_tif)) {
      return 0;
    }

    lvar_t &dest_var = var_ref.mba->vars[var_ref.idx];
    func_t *func = get_func(e->ea);
    if (func == nullptr) {
      return 0;
    }
    if (set_var_type(func->start_ea, dest_var, shifted_tif)) {
      efi_utils::log("shifted pointer applied at 0x%" PRIx64 "\n",
                     u64_addr(e->ea));
    }

    if (call) {
      efi_utils::op_stroff(e->ea, "EFI_PEI_SERVICES");
    }

    return 0;
  }

protected:
  bool m_debug = true;
};

class pei_services_detector_arm_t : public ctree_visitor_t {
  // detect and mark all PEI services for ARM firmware
  // tested on Ampere firmware that contains small PEI stack
public:
  pei_services_detector_arm_t() : ctree_visitor_t(CV_FAST) {}

  json_list_t m_services;

  // this is the callback function that Hex-Rays invokes for every expression
  // in the CTREE
  int visit_expr(cexpr_t *e) {
    if (!(e->op == cot_call && e->x->op == cot_memptr &&
          e->x->x->op == cot_ptr && e->x->x->x->op == cot_var)) {
      return 0;
    }
    ea_t offset = e->x->m;

    // check if service from EFI_PEI_SERVICES
    tinfo_t table_type = e->x->x->type;
    tinfo_t table_type_no_ptr;
    qstring table_type_name;
    if (table_type.is_ptr()) {
      table_type_no_ptr = remove_pointer(table_type);
      table_type_no_ptr.get_type_name(&table_type_name);
    } else {
      table_type.get_type_name(&table_type_name);
    }

    // get service name from function type
    std::string service_name;
    if (table_type_name != "EFI_PEI_SERVICES") {
      qstring func_type_name;
      tinfo_t service_type = e->x->type;
      service_type.get_type_name(&func_type_name);
      std::string func_type = func_type_name.c_str();
      std::string prefix = "EFI_PEI_";
      if (func_type.substr(0, prefix.length()) == prefix) {
        func_type.erase(0, prefix.length());
      }
      service_name = efi_utils::type_to_name(func_type);
    } else {
      auto s = m_pei_services.find(offset);
      if (s == m_pei_services.end()) {
        return 0;
      }
      service_name = s->second;
    }
    if (m_debug) {
      efi_utils::log("0x%" PRIx64 ": %s service detected (offset: %d): %s\n",
                     u64_addr(e->ea), table_type_name.c_str(), u32_addr(offset),
                     service_name.c_str());
    }

    json s;
    s["address"] = e->ea;
    s["service_name"] = service_name;
    s["table_name"] = table_type_name.c_str();

    if (!efi_utils::json_in_vec(m_services, s)) {
      m_services.push_back(s);
    }

    return 0;
  }

protected:
  bool m_debug = true;
  std::map<ea_t, std::string> m_pei_services = {
      {0x18, "InstallPpi"},
      {0x20, "ReInstallPpi"},
      {0x28, "LocatePpi"},
      {0x30, "NotifyPpi"},
      {0x38, "GetBootMode"},
      {0x40, "SetBootMode"},
      {0x48, "GetHobList"},
      {0x50, "CreateHob"},
      {0x58, "FfsFindNextVolume"},
      {0x60, "FfsFindNextFile"},
      {0x68, "FfsFindSectionData"},
      {0x70, "InstallPeiMemory"},
      {0x78, "AllocatePages"},
      {0x80, "AllocatePool"},
      {0x88, "CopyMem"},
      {0x90, "SetMem"},
      {0x98, "ReportStatusCode"},
      {0xA0, "ResetSystem"},
      {0xA8, "CpuIo"},
      {0xB0, "PciCfg"},
      {0xB8, "FfsFindFileByName"},
      {0xC0, "FfsGetFileInfo"},
      {0xC8, "FfsGetVolumeInfo"},
      {0xD0, "RegisterForShadow"},
      {0xD8, "FindSectionData4"},
      {0xE0, "FfsGetFileInfo3"},
      {0xE8, "ResetSystem3"},
  };
};
} // namespace efi_hexrays
