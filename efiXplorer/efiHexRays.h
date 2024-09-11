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
 * efiHexRays.h
 *
 */

#pragma once

#include "efiUtils.h"

uint8_t VariablesInfoExtractAll(func_t *f, ea_t code_addr);
bool TrackEntryParams(func_t *f, uint8_t depth);
json DetectVars(func_t *f);
std::vector<json> DetectServices(func_t *f);
std::vector<json> DetectPeiServicesArm(func_t *f);
bool DetectPeiServices(func_t *f);
bool setLvarName(qstring name, lvar_t lvar, ea_t func_addr);
bool applyAllTypesForInterfacesBootServices(std::vector<json> guids);
bool applyAllTypesForInterfacesSmmServices(std::vector<json> guids); // unused
bool setHexRaysVariableInfo(ea_t funcEa, lvar_t &ll, tinfo_t tif, std::string name);
bool setHexRaysVariableInfoAndHandleInterfaces(ea_t funcEa, lvar_t &ll, tinfo_t tif,
                                               std::string name);
bool offsetOf(tinfo_t tif, const char *name, unsigned int *offset);
bool isPODArray(tinfo_t tif, unsigned int ptrDepth);
const char *Expr2String(cexpr_t *e, qstring *out);

// Description of a function pointer within a structure. Ultimately, this
// plugin is looking for calls to specific UEFI functions. This structure
// describes basic information about those functions:
struct TargetFunctionPointer {
  const char *name;      // Name of function pointer in structure
  int offset;            // Offset of function pointer (filled in later)
  unsigned int nArgs;    // Number of expected arguments
  unsigned int nGUIDArg; // Which argument has the EFI_GUID *
  unsigned int nOutArg;  // Which argument retrieves the output
};

// This class holds all function pointer descriptors for one structure, as well
// as providing a utility to look up function pointers by offset.
class ServiceDescriptor {
  // Instance data
protected:
  // The type of the containing structure (e.g. EFI_BOOT_SERVICES)
  tinfo_t mType;

  // The name of the type (e.g. "EFI_BOOT_SERVICES")
  qstring mName;

  // The ordinal of the type (e.g. 4)
  uint32 mOrdinal;

  // A vector of the structures above, copied, and with the offsets filled in
  std::vector<TargetFunctionPointer> mTargets;

  bool bInitialized;

  // Ensure we can look up the type that this instance describes
  bool InitType(const char *name) {
    // Import type
    import_type(get_idati(), -1, name);

    // Get type by name
    if (!mType.get_named_type(get_idati(), name))
      return false;

    // Save ordinal and name
    mOrdinal = mType.get_ordinal();
    mName = name;
    return true;
  }

  // Look up the offsets for all function pointer targets; save the results
  // in the vector. Return false if offset lookup fails.
  bool InitTargets(TargetFunctionPointer *targets, size_t num) {
    // Iterate through all targets
    for (int i = 0; i < num; ++i) {

      // Copy the target structure into our local vector
      TargetFunctionPointer &tgt = mTargets.emplace_back();
      tgt = targets[i];

      // Retrieve the offsets of each named function pointer
      unsigned int offset;
      if (!offsetOf(mType, targets[i].name, &offset)) {
        return false;
      }
    }
    return true;
  }

public:
  // Constructor does nothing
  ServiceDescriptor() : mOrdinal(0), bInitialized(false) {};

  // Accessor for ordinal
  uint32 GetOrdinal() { return mOrdinal; };

  // Accessor for name
  const char *GetName() { return mName.c_str(); };

  // Needs to be called before the object can be used
  bool Initialize(const char *name, TargetFunctionPointer *targets, size_t num) {
    if (bInitialized)
      return true;
    bInitialized = InitType(name) && InitTargets(targets, num);
    return bInitialized;
  }

  // After initialization, look up a target by offset
  bool LookupOffset(unsigned int offset, TargetFunctionPointer **tgt) {
    // Iterating through a vector generally is inefficient compared to a map,
    // but there are at most 3 function pointers so far, so it outweighs the
    // overhead of the associative containers.
    for (auto &it : mTargets) {
      // Match by offset
      if (it.offset == offset) {
        *tgt = &it;
        return true;
      }
    }
    // If we don't find it, it's not necessarily "bad" from the point of view
    // of the plugin's logic. After all, we're looking at every access to the
    // selected structures, and so, quite rightly, we'll want to ignore the
    // function pointers that we're not tracking.
    return false;
  }
};

// This class manages multiple instances of the class above. Each such
// structure is associated with the ordinal of its containing structure type.
// Then, when the Hex-Rays visitor needs to look up a function pointer access
// into a structure, it just passes the structure ordinal and offset. This
// class looks up the ServiceDescriptor in a map by ordinal, and then looks up
// the offset if that succeeded.
class ServiceDescriptorMap {
protected:
  // Our map for looking up ServiceDescriptor structures. I should probably
  // change the value type to a pointer.
  std::map<uint32, ServiceDescriptor> mServices;

public:
  // Add a new ServiceDescriptor to the map. I should change the argument
  // type to match whatever I change the value type of the map to.
  bool Register(ServiceDescriptor sd) {

    // Get the ordinal from the ServiceDescriptor
    uint32 ord = sd.GetOrdinal();

    // Are we already tracking this structure?
    if (mServices.find(ord) != mServices.end()) {
      return false;
    }
    // If not, register it. Get rid of std::move
    mServices[ord] = std::move(sd);
    return true;
  }

  // This function could be protected, but whatever. Given an ordinal, get
  // the tracked ServiceDescriptor, if applicable.
  bool LookupOrdinal(uint32 ord, ServiceDescriptor **sd) {
    auto it = mServices.find(ord);
    if (it == mServices.end()) {
      return false;
    }
    *sd = &it->second;
    return true;
  }

  // This is the high-level function that clients call. Given a structure
  // ordinal and offset of a function pointer, see if it's something we're
  // tracking. If so, get pointers to the tracked objects and return true.
  bool LookupOffset(uint32 ord, unsigned int offset, ServiceDescriptor **sd,
                    TargetFunctionPointer **tgt) {
    if (!LookupOrdinal(ord, sd))
      return false;
    if (!(*sd)->LookupOffset(offset, tgt))
      return false;
    return true;
  }
};

// Base class for two visitors that require similar functionality. Here we
// collect all of the common data and functionality that will be used by both
// of those visitors. This allows the derivatives to be very succinct.
class GUIDRelatedVisitorBase : public ctree_visitor_t {
public:
  // We need access to a ServiceDescriptorMap from above.
  GUIDRelatedVisitorBase(ServiceDescriptorMap &m)
      : ctree_visitor_t(CV_FAST), mDebug(true), mServices(m) {};

  // We need the function ea when setting Hex-Rays variable types.
  void SetFuncEa(ea_t ea) { mFuncEa = ea; };
  void SetCodeEa(ea_t ea) { mCodeEa = ea; };
  void SetProtocols(std::vector<json> protocols) { mProtocols = protocols; };

protected:
  //
  // Persistent variables
  //

  // Function address
  ea_t mFuncEa;
  ea_t mCodeEa;

  // Protocols
  std::vector<json> mProtocols;

  // Print debug messages?
  bool mDebug = false;

  // Used for looking up calls to function pointers in structures
  ServiceDescriptorMap &mServices;

  //
  // State variables, cleared on every iteration. I debated with myself
  // whether this was a nasty design decision. I think it's fine. These
  // variables are only valid to access after the client has called
  // ValidateCallAndGUID, and it returned true. If you called that and it
  // returned false, these will be in an inconsistent state. Don't touch them
  // if that's the case.
  //

  // Address of the indirect function call
  ea_t mEa;

  // The pointer type that's being accessed (that of the structure)
  tinfo_t mTif;

  // The structure type, with the pointer indirection removed
  tinfo_t mTifNoPtr;

  // The ServiceDescriptor for the containing structure
  ServiceDescriptor *mpService;

  // The ordinal of the structure type
  uint32 mOrdinal;

  // The offset of the function pointer in the structure
  unsigned int mOffset;

  // Details about the target of the indirect call (e.g. name)
  TargetFunctionPointer *mpTarget;

  // The list of arguments for the indirect call
  carglist_t *mArgs;

  // The argument that specifies the GUID for the indirect call
  cexpr_t *mGUIDArg;

  // The argument that gets the output for the indirect call
  cexpr_t *mOutArg;

  // The GUID argument will be &x; this is x
  cexpr_t *mGUIDArgRefTo;

  // The address of the GUID being passed to the indirect call
  ea_t mGUIDEa;

  // This function clears all the state variables above. Technically, it
  // doesn't need to exist, since the flow of logic in the functions below
  // always write to them before reading to them. But, it seems like good
  // programming practice not to have stale values, anyway.
  void Clear() {
    mEa = BADADDR;
    mTif.clear();
    mTifNoPtr.clear();
    mpService = nullptr;
    mOrdinal = 0;
    mOffset = -1;
    mpTarget = nullptr;
    mArgs = nullptr;
    mGUIDArg = nullptr;
    mOutArg = nullptr;
    mGUIDArgRefTo = nullptr;
    mGUIDEa = BADADDR;
  };

  // Debug print, if the instance debug variable says to
  void DebugPrint(const char *fmt, ...) {
    va_list va;
    va_start(va, fmt);
    if (mDebug)
      vmsg(fmt, va);
  };

  // This is the first function called every time the visitor visits an
  // expression. This function determines if the expression is a call to a
  // function pointer contained in a structure.
  bool GetICallOrdAndOffset(cexpr_t *e) {
    // Set instance variable for call address
    mEa = e->ea;

    if (mEa != mCodeEa) {
      return false;
    }

    // If it's not a call, we're done.
    if (e->op != cot_call)
      return false;

    // Set instance variable with call arguments
    mArgs = e->a;

    // If it's a direct call, we're done.
    cexpr_t *callDest = e->x;
    if (callDest->op == cot_obj)
      return false;

    // Eat any casts on the type of what's being called
    while (callDest->op == cot_cast)
      callDest = callDest->x;

    // If the destination is not a member of a structure, we're done.
    if (callDest->op != cot_memptr)
      return false;

    // Set instance variable with type of structure containing pointer
    mTif = callDest->x->type;

    // Ensure that the structure is being accessed via pointer, and not as a
    // reference (i.e., through a structure held on the stack as a local
    // variable).
    if (!mTif.is_ptr()) {
      return false;
    }

    // Remove pointer from containing structure type, set instance variable
    mTifNoPtr = remove_pointer(mTif);

    // Get the ordinal of the structure
    mOrdinal = mTifNoPtr.get_ordinal();

    // If we can't get a type for the structure, that's bad
    if (mOrdinal == 0)
      return false;

    // Get the offset of the function pointer in the structure
    mOffset = callDest->m;

    // Okay: now we know we're dealing with an indirect call to a function
    // pointer contained in a structure, where the structure is being
    // accessed by a pointer.
    return true;
  };

  // This is the second function called as part of indirect call validation.
  // Now we want to know: is it a call to something that we're tracking?
  bool ValidateICallDestination() {

    // Look up the structure ordinal and function offset; get the associated
    // ServiceDescriptor and TargetFunctionPointer (instance variables).
    if (!mServices.LookupOffset(mOrdinal, mOffset, &mpService, &mpTarget))
      return false;

    // Great, it was something that we were tracking. Now, sanity-check the
    // number of arguments on the function call. (Hex-Rays might have gotten
    // this wrong. The user can fix it via "set call type".)
    size_t mArgsSize = mArgs->size();
    size_t nArgs = mpTarget->nArgs;
    if (mArgsSize != nArgs) {
      return false;
    }

    // The TargetFunctionPointer tells us which argument takes an EFI_GUID *,
    // and which one retrieves the output. Get those arguments, and save them
    // as instance variables.
    mGUIDArg = &mArgs->at(mpTarget->nGUIDArg);
    mOutArg = &mArgs->at(mpTarget->nOutArg);

    // Great; now we know that the expression is an indirect call to
    // something that we're tracking, and that Hex-Rays decompiled the call
    // the way we expected it to.
    return true;
  };

  // This is a helper function used to get the thing being referred to. What
  // does that mean?
  //
  // * For GUID arguments, we'll usually have &globvar. Return globvar.
  // * For output arguments, we'll usually have &globvar or &locvar. Due to
  //   Hex-Rays internal heuristics, we might end up with "locarray", which
  //   does not actually have a "&" when passed as a call argument. There's
  //   a bit of extra logic to check for that case.
  cexpr_t *GetReferent(cexpr_t *e, const char *desc, bool bAcceptVar) {

    // Eat casts
    cexpr_t *x = e;
    while (x->op == cot_cast)
      x = x->x;

    qstring estr;
    // If we're accepting local variables, and this is a variable (note: not
    // a *reference* to a variable)
    if (bAcceptVar && x->op == cot_var) {
      // Get the variable details
      var_ref_t varRef = x->v;
      lvar_t destVar = varRef.mba->vars[varRef.idx];

      // Ensure that it's an array of POD types, or pointers to them
      bool bisPODArray = isPODArray(destVar.tif, 1);

      // If it is a POD array, good, we'll take it.
      return bisPODArray ? x : nullptr;
    }

    // For everything else, we really want it to be a reference: either to a
    // global or local variable. If it's not a reference, we can't get the
    // referent, so fail.
    if (x->op != cot_ref) {
      return nullptr;
    }

    // If we get here, we know it's a reference. Return the referent.
    return x->x;
  };

  // The third function in the validation logic. We already know the
  // expression is an indirect call to something that we're tracking, and
  // that Hex-Rays' decompilation matches on the number of arguments. Now,
  // we validate that the GUID argument does in fact point to a global
  // variable.
  bool ValidateGUIDArgument() {
    // Does the GUID argument point to a local variable?
    mGUIDArgRefTo = GetReferent(mGUIDArg, "GUID", false);
    if (!mGUIDArgRefTo)
      return false;

    // If we get here, we know it was a reference to *something*. Ensure that
    // something is a global variable.
    if (mGUIDArgRefTo->op != cot_obj) {
      return false;
    }

    // Save the address of the global variable to which the GUID argument is
    // pointing.
    mGUIDEa = mGUIDArgRefTo->obj_ea;

    // Great; now we know we're dealing with an indirect call to something
    // we're tracking; that Hex-Rays decompiled the call with the proper
    // number of arguments; and that the GUID argument did in fact point to
    // a global variable, whose address we now have in an instance variable.
    return true;
  };

  // Finally, this function combines all three checks above into one single
  // function. If you call this and it returns true, feel free to access the
  // instance variables, as they are guaranteed to be valid. If it returns
  // false, they aren't, so don't touch them.
  bool ValidateCallAndGUID(cexpr_t *e) {
    // Reset all instance variables. Not strictly necessary; call it
    // "defensive programming".
    Clear();

    // Validate according to the logic above.
    if (!GetICallOrdAndOffset(e) || !ValidateICallDestination() ||
        !ValidateGUIDArgument())
      return false;

    // Good, all checks passed
    return true;
  }
};

// Now that we've implemented all that validation logic, this class is pretty
// simple. This one is responsible for ensuring that the GUID is something that
// we know about, and setting the types of the output variables accordingly.
class GUIDRetyper : public GUIDRelatedVisitorBase {
public:
  GUIDRetyper(ServiceDescriptorMap &m) : GUIDRelatedVisitorBase(m), mNumApplied(0) {};

  // This is the callback function that Hex-Rays invokes for every expression
  // in the CTREE.
  int visit_expr(cexpr_t *e) {
    // Perform the checks from GUIDRelatedVisitorBase. If they fail, we're
    // not equipped to deal with this expression, so bail out.
    if (!ValidateCallAndGUID(e))
      return 0;

    mGUIDArgRefTo = GetReferent(mGUIDArg, "GUID", false);
    if (mGUIDArgRefTo == nullptr)
      return 0;
    ea_t guidAddr = mGUIDArgRefTo->obj_ea;

    // Get interface type name
    std::string GUIDName;
    for (auto g : mProtocols) {
      if (guidAddr == g["address"]) {
        GUIDName = g["prot_name"];
        break;
      }
    }
    if (GUIDName.empty()) {
      return 0;
    }

    std::string interfaceTypeName = GUIDName.substr(0, GUIDName.find("_GUID"));
    if (!interfaceTypeName.find("FCH_")) {
      // convert FCH_SMM_* dispatcher type to EFI_SMM_* dispatcher type
      interfaceTypeName.replace(0, 4, "EFI_");
    }

    // Need to get the type for the interface variable here
    tinfo_t tif;
    import_type(get_idati(), -1, interfaceTypeName.c_str());
    if (!tif.get_named_type(get_idati(), interfaceTypeName.c_str())) {
      // Get the referent for the interface argument.
      cexpr_t *outArgReferent = GetReferent(mOutArg, "ptr", true);
      if (outArgReferent == nullptr)
        return 0;
      ApplyName(outArgReferent, interfaceTypeName);
      return 0;
    }

    qstring tStr;
    if (!tif.get_type_name(&tStr)) {
      return 0;
    }

    tinfo_t tifGuidPtr;
    if (!tifGuidPtr.create_ptr(tif)) {
      return 0;
    }

    // Get the referent for the interface argument.
    cexpr_t *outArgReferent = GetReferent(mOutArg, "ptr", true);
    if (outArgReferent == nullptr)
      return 0;

    // Apply the type to the output referent.
    ApplyType(outArgReferent, tifGuidPtr, tStr);
    return 1;
  }

protected:
  unsigned int mNumApplied;

  // Given an expression (either a local or global variable) and a type to
  // apply, apply the type. This is just a bit of IDA/Hex-Rays type system
  // skullduggery.
  void ApplyType(cexpr_t *outArg, tinfo_t ptrTif, qstring tStr) {
    ea_t dest_ea = outArg->obj_ea;

    // For global variables
    if (outArg->op == cot_obj) {
      // Just apply the type information to the address
      apply_tinfo(dest_ea, ptrTif, TINFO_DEFINITE);
      ++mNumApplied;

      // Rename global variable
      auto name = "g" + typeToName(static_cast<std::string>(tStr.c_str()));
      set_name(dest_ea, name.c_str(), SN_FORCE);

      // Get xrefs to global variable
      auto xrefs = getXrefs(dest_ea);
      qstring typeName;
      ptr_type_data_t pi;
      ptrTif.get_ptr_details(&pi);
      pi.obj_type.get_type_name(&typeName);
      // Handling all interface functions (to rename function arguments)
      opstroffForGlobalInterface(xrefs, typeName);
    }

    // For local variables
    else if (outArg->op == cot_var) {
      var_ref_t varRef = outArg->v;
      lvar_t &destVar = varRef.mba->vars[varRef.idx];
      // Set the Hex-Rays variable type
      auto name = typeToName(static_cast<std::string>(tStr.c_str()));
      setLvarName(static_cast<qstring>(name.c_str()), destVar, mFuncEa);
      if (setHexRaysVariableInfoAndHandleInterfaces(mFuncEa, destVar, ptrTif, name)) {
        ++mNumApplied;
      }
    }
  }

  void ApplyName(cexpr_t *outArg, std::string type_name) {
    ea_t dest_ea = outArg->obj_ea;

    // For global variables
    if (outArg->op == cot_obj) {
      // Rename global variable
      auto name = "g" + typeToName(type_name);
      set_name(dest_ea, name.c_str(), SN_FORCE);
    }

    // For local variables
    else if (outArg->op == cot_var) {
      var_ref_t varRef = outArg->v;
      lvar_t &destVar = varRef.mba->vars[varRef.idx];
      // Set the Hex-Rays variable type
      auto name = typeToName(type_name);
      setLvarName(static_cast<qstring>(name.c_str()), destVar, mFuncEa);
    }
  }
};

class VariablesInfoExtractor : public ctree_visitor_t {
public:
  VariablesInfoExtractor(ea_t code_addr) : ctree_visitor_t(CV_FAST) {
    mCodeAddr = code_addr;
  };

  uint8_t mAttributes = 0xff;

  // This is the callback function that Hex-Rays invokes for every expression
  // in the CTREE.
  int visit_expr(cexpr_t *e) {
    if (mCodeAddr == BADADDR) {
      return 0;
    }

    if (e->ea != mCodeAddr) {
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
      if (mDebug) {
        msg("[I] Service call: %016llX, Attributes: %02X\n", u64_addr(mCodeAddr),
            static_cast<uint8_t>(attributes_arg->numval()));
      }
      attributes_arg->numval();
      mAttributes = static_cast<uint8_t>(attributes_arg->numval());
    }

    return 0;
  }

protected:
  ea_t mCodeAddr = BADADDR;
  bool mDebug = false;
};

class PrototypesFixer : public ctree_visitor_t {
public:
  PrototypesFixer() : ctree_visitor_t(CV_FAST) {};
  std::vector<ea_t> child_functions;

  // This is the callback function that Hex-Rays invokes for every expression
  // in the CTREE.
  int visit_expr(cexpr_t *e) {
    if (e->op != cot_call)
      return 0;

    // get child function address
    if (e->x->op != cot_obj) {
      return 0;
    }
    if (mDebug) {
      msg("[I] Child function address: %016llX\n", u64_addr(e->x->obj_ea));
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

    msg("[I] Call address: 0x%016llX\n", u64_addr(e->ea));
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
        bool is_ptr = false;
        if (!arg_type.get_type_name(&type_name)) {
          if (!arg_type_no_ptr.get_type_name(&type_name)) {
            // msg("[E] Can not get type name: 0x%016llX\n", u64_addr(e->ea));
            continue;
          }
          is_ptr = true;
        }

        if (is_ptr) {
          msg("[I]  Arg #%d, type =  %s *\n", i, type_name.c_str());
        } else {
          msg("[I]  Arg #%d, type =  %s\n", i, type_name.c_str());
        }

        if (type_name == qstring("EFI_HANDLE") ||
            type_name == qstring("EFI_SYSTEM_TABLE")) {
          if (!addrInVec(child_functions, func_addr)) {
            child_functions.push_back(func_addr);
          }
          // set argument type and name
          if (cf->argidx.size() <= i) {
            return 0;
          }
          auto argid = cf->argidx[i];
          lvar_t &arg_var = cf->mba->vars[argid]; // get lvar for argument
          if (type_name == qstring("EFI_HANDLE")) {
            setHexRaysVariableInfo(func_addr, arg_var, arg_type, "ImageHandle");
          }
          if (type_name == qstring("EFI_SYSTEM_TABLE")) {
            setHexRaysVariableInfo(func_addr, arg_var, arg_type, "SystemTable");
          }
        }
      }
    }

    return 0;
  }

protected:
  bool mDebug = true;
};

class VariablesDetector : public ctree_visitor_t {
public:
  VariablesDetector() : ctree_visitor_t(CV_FAST) {};

  std::vector<ea_t> child_functions;

  std::vector<ea_t> gImageHandleList;
  std::vector<ea_t> gStList;
  std::vector<ea_t> gBsList;
  std::vector<ea_t> gRtList;

  void SetFuncEa(ea_t ea) { mFuncEa = ea; };

  // This is the callback function that Hex-Rays invokes for every expression
  // in the CTREE.
  int visit_expr(cexpr_t *e) {
    if (e->op == cot_asg) {
      // saving a child function for recursive analysis
      if (!addrInVec(child_functions, e->ea)) {
        child_functions.push_back(e->x->obj_ea);
      }
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

    if (e->y->op != cot_cast && e->y->op != cot_var) {
      return 0;
    }

    // extract variable type
    tinfo_t var_type;
    tinfo_t var_type_no_ptr;
    if (e->y->op == cot_var) {
      var_type = e->y->type;
    }
    if (e->y->op == cot_cast) {
      var_type = e->y->x->type;
    }

    if (var_type.is_ptr()) {
      var_type_no_ptr = remove_pointer(var_type);
    }

    qstring type_name;
    bool is_ptr = false;
    if (!var_type.get_type_name(&type_name)) {
      if (!var_type_no_ptr.get_type_name(&type_name)) {
        // msg("[E] can not get type name: 0x%016llX\n", u64_addr(e->ea));
        return 0;
      }
      is_ptr = true;
    }

    if (mDebug) {
      msg("[I] code address: 0x%016llX, type name: %s\n", u64_addr(e->ea),
          type_name.c_str());
    }

    if (global_var) {
      // extract variable data
      ea_t g_addr = e->x->obj_ea;
      std::string type_name_str = static_cast<std::string>(type_name.c_str());
      if (type_name == qstring("EFI_HANDLE")) {
        setTypeAndName(g_addr, "gImageHandle", type_name_str);
        if (!addrInVec(gImageHandleList, g_addr)) {
          gImageHandleList.push_back(g_addr);
        }
      }
      if (type_name == qstring("EFI_SYSTEM_TABLE")) {
        setPtrTypeAndName(g_addr, "gST", type_name_str);
        if (!addrInVec(gStList, g_addr)) {
          gStList.push_back(g_addr);
        }
      }
      if (type_name == qstring("EFI_BOOT_SERVICES")) {
        setPtrTypeAndName(g_addr, "gBS", type_name_str);
        if (!addrInVec(gBsList, g_addr)) {
          gBsList.push_back(g_addr);
        }
      }
      if (type_name == qstring("EFI_RUNTIME_SERVICES")) {
        setPtrTypeAndName(g_addr, "gRT", type_name_str);
        if (!addrInVec(gRtList, g_addr)) {
          gRtList.push_back(g_addr);
        }
      }
    }

    if (local_var) {
      var_ref_t var_ref;
      if (e->y->op == cot_var) {
        var_ref = e->y->v;
      }
      if (e->y->op == cot_cast) {
        var_ref = e->y->x->v;
      }
      lvar_t &dest_var = var_ref.mba->vars[var_ref.idx];
      // Set the Hex-Rays variable type
      auto name = typeToName(static_cast<std::string>(type_name.c_str()));
      // setHexRaysVariableInfo(mFuncEa, dest_var, var_type, name);
    }

    return 0;
  }

protected:
  bool mDebug = true;
  ea_t mFuncEa = BADADDR;
};

class ServicesDetector : public ctree_visitor_t {
  // detect all services (Boot services, Runtime services, etc)
public:
  ServicesDetector() : ctree_visitor_t(CV_FAST) {};

  std::vector<json> services;

  // This is the callback function that Hex-Rays invokes for every expression
  // in the CTREE.
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
        // msg("[E] can not get type name: 0x%016llX\n", u64_addr(e->ea));
        return 0;
      }
      is_ptr = 0;
    }

    auto service_name = typeToName(static_cast<std::string>(type_name.c_str()));
    if (service_name.rfind("Efi", 0) == 0) {
      service_name = service_name.substr(3);
      if (service_name == "RaiseTpl") {
        service_name = "RaiseTPL";
      }
      if (service_name == "RestoreTpl") {
        service_name = "RestoreTPL";
      }
    }
    msg("[efiXplorer] address: 0x%016llX, service type: %s, service name: %s\n",
        u64_addr(e->ea), type_name.c_str(), service_name.c_str());

    // append service
    // add item to allBootServices
    json s;
    s["address"] = e->ea;
    s["service_name"] = service_name;
    s["table_name"] = getTable(service_name);

    if (!jsonInVec(services, s)) {
      services.push_back(s);
    }

    return 0;
  }

protected:
  bool mDebug = true;
};

class PeiServicesDetector : public ctree_visitor_t {
  // detect and mark all PEI services
public:
  PeiServicesDetector() : ctree_visitor_t(CV_FAST) {};

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

  // This is the callback function that Hex-Rays invokes for every expression
  // in the CTREE.
  int visit_expr(cexpr_t *e) {
    auto pointer_offset = BADADDR;
    auto service_offset = BADADDR;
    bool call = false;
    var_ref_t var_ref;
    if (e->op == cot_ptr && e->x->op == cot_cast && e->x->x->op == cot_add &&
        e->x->x->x->op == cot_ptr && e->x->x->x->x->op == cot_ptr &&
        e->x->x->x->x->x->op == cot_cast && e->x->x->x->x->x->x->op == cot_sub &&
        e->x->x->x->x->x->x->x->op == cot_var && e->x->x->x->x->x->x->y->op == cot_num &&
        e->x->x->y->op == cot_num) {
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

    msg("[efiXplorer] address: 0x%08llX, PEI service detected\n", u64_addr(e->ea));
    msg("[efiXplorer]   delta: %llx\n", u64_addr(pointer_offset));
    if (service_offset != BADADDR) {
      msg("[efiXplorer]   service offset: %llx\n", u64_addr(service_offset));
    }

    if (pointer_offset != 4) {
      return 0;
    }

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
      msg("[efiXplorer] shifted pointer applied (0x%08llX)\n", u64_addr(e->ea));
    }

    if (call) {
      opStroff(e->ea, "EFI_PEI_SERVICES");
    }

    return 0;
  }

protected:
  bool mDebug = true;
};

class PeiServicesDetectorArm : public ctree_visitor_t {
  // detect and mark all PEI services for ARM firmware
  // tested on Ampere firmware that contains small PEI stack
public:
  PeiServicesDetectorArm() : ctree_visitor_t(CV_FAST) {};

  std::vector<json> services;

  // This is the callback function that Hex-Rays invokes for every expression
  // in the CTREE.
  int visit_expr(cexpr_t *e) {
    if (!(e->op == cot_call && e->x->op == cot_memptr && e->x->x->op == cot_ptr &&
          e->x->x->x->op == cot_var)) {
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
      std::string func_type = static_cast<std::string>(func_type_name.c_str());
      std::string prefix = "EFI_PEI_";
      if (func_type.substr(0, prefix.length()) == prefix) {
        func_type.erase(0, prefix.length());
      }
      service_name = typeToName(func_type);
    } else {
      auto s = mPeiServices.find(offset);
      if (s == mPeiServices.end()) {
        return 0;
      }
      service_name = s->second;
    }
    if (mDebug) {
      msg("[efiXplorer] 0x%08llX: %s service detected (offset: %d): %s\n",
          u64_addr(e->ea), table_type_name.c_str(), u32_addr(offset),
          service_name.c_str());
    }

    json s;
    s["address"] = e->ea;
    s["service_name"] = service_name;
    s["table_name"] = table_type_name.c_str();

    if (!jsonInVec(services, s)) {
      services.push_back(s);
    }

    return 0;
  }

protected:
  bool mDebug = true;
  std::map<ea_t, std::string> mPeiServices = {
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
