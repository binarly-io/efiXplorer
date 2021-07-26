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
 * efiHexRays.h
 *
 */

#pragma once

#include "efiUtils.h"

void applyAllTypesForInterfaces(std::vector<json> guids);
bool SetHexRaysVariableType(ea_t funcEa, lvar_t &ll, tinfo_t tif);
bool OffsetOf(tinfo_t tif, const char *name, unsigned int *offset);
bool IsPODArray(tinfo_t tif, unsigned int ptrDepth);
const char *Expr2String(cexpr_t *e, qstring *out);

// Description of a function pointer within a structure. Ultimately, this
// plugin is looking for calls to specific UEFI functions. This structure
// describes basic information about those functions:
struct TargetFunctionPointer {
    char *name;            // Name of function pointer in structure
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
        if (!mType.get_named_type(get_idati(), name, BTF_STRUCT))
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
            if (!OffsetOf(mType, targets[i].name, &offset)) {
                msg("[E] Could not get offset of %s\n", targets[i].name);
                return false;
            }
        }
        return true;
    }

  public:
    // Constructor does nothing
    ServiceDescriptor() : mOrdinal(0), bInitialized(false){};

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
        msg("[I] Could not find function pointer with offset 0x%a\n", offset);
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
            msg("[E] Ordinal %x already registered\n", ord);
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
            msg("[E] Could not find ordinal %x\n", ord);
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
        : ctree_visitor_t(CV_FAST), mDebug(true), mServices(m){};

    // We need the function ea when setting Hex-Rays variable types.
    void SetFuncEa(ea_t ea) { mFuncEa = ea; };
    void SetProtocols(std::vector<json> protocols) { mProtocols = protocols; };

  protected:
    //
    // Persistent variables
    //

    // Function address
    ea_t mFuncEa;

    // Protocols
    std::vector<json> mProtocols;

    // Print debug messages?
    bool mDebug = true;

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
            DebugPrint("%a: variable is not a pointer?\n", mEa);
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
            DebugPrint("[E] Call to %s::%s had %d args instead of %d expected\n",
                       mpService->GetName(), mpTarget->name, mArgsSize, nArgs);
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
            bool bIsPodArray = IsPODArray(destVar.tif, 1);

            // Debug printing
            DebugPrint("[I] %a Was indirect call from %s::%s, but %s arg was %s, not "
                       "reference [IsPODArray: %d]\n",
                       mEa, mpService->GetName(), mpTarget->name, desc,
                       Expr2String(e, &estr), bIsPodArray);

            // If it is a POD array, good, we'll take it.
            return bIsPodArray ? x : nullptr;
        }

        // For everything else, we really want it to be a reference: either to a
        // global or local variable. If it's not a reference, we can't get the
        // referent, so fail.
        if (x->op != cot_ref) {
            DebugPrint("[I] %a Was indirect call from %s::%s, but %s arg was %s, not "
                       "reference\n",
                       mEa, mpService->GetName(), mpTarget->name, desc,
                       Expr2String(e, &estr));
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
            qstring estr;
            DebugPrint("[I] %a Was indirect call from %s::%s, but GUID arg was %s, not "
                       "reference to global\n",
                       mEa, mpService->GetName(), mpTarget->name,
                       Expr2String(mGUIDArgRefTo, &estr));
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
    GUIDRetyper(ServiceDescriptorMap &m) : GUIDRelatedVisitorBase(m), mNumApplied(0){};

    // This is the callback function that Hex-Rays invokes for every expression
    // in the CTREE.
    int visit_expr(cexpr_t *e) {
        // Perform the checks from GUIDRelatedVisitorBase. If they fail, we're
        // not equipped to deal with this expression, so bail out.
        if (!ValidateCallAndGUID(e))
            return 0;

        // At this point, the address of the GUID is in member mGUIDEa
        // I need to look that up in the GUID information and get its name
        // Also needs to handle the case where the name is unknown and return 0
        // Until I know how to do that, I'm hard-coding this example string
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

        // Need to get the type for the interface variable here
        tinfo_t tif;
        import_type(get_idati(), -1, interfaceTypeName.c_str());
        if (!tif.get_named_type(get_idati(), interfaceTypeName.c_str())) {
            return 0;
        }

        qstring tStr;
        if (!tif.get_type_name(&tStr)) {
            DebugPrint("[E] Can't get type name\n");
            return 0;
        }

        DebugPrint("[I] Protocol type name: %s\n", tStr.c_str());

        tinfo_t tifGuidPtr;
        if (!tifGuidPtr.create_ptr(tif)) {
            return 0;
        }

        // Get the referent for the interface argument.
        cexpr_t *outArgReferent = GetReferent(mOutArg, "ptr", true);
        if (outArgReferent == nullptr)
            return 0;

        // Apply the type to the output referent.
        ApplyType(outArgReferent, tifGuidPtr);
        return 1;
    }

  protected:
    unsigned int mNumApplied;

    // Given an expression (either a local or global variable) and a type to
    // apply, apply the type. This is just a bit of IDA/Hex-Rays type system
    // skullduggery.
    void ApplyType(cexpr_t *outArg, tinfo_t ptrTif) {
        ea_t dest_ea = outArg->obj_ea;

        // For global variables
        if (outArg->op == cot_obj) {
            // Just apply the type information to the address
            apply_tinfo(dest_ea, ptrTif, TINFO_DEFINITE);
            ++mNumApplied;
            DebugPrint("%a: %s::%s applied type for global variable\n", mEa,
                       mpService->GetName(), mpTarget->name);
        }

        // For local variables
        else if (outArg->op == cot_var) {
            var_ref_t varRef = outArg->v;
            lvar_t &destVar = varRef.mba->vars[varRef.idx];
            // Set the Hex-Rays variable type
            if (SetHexRaysVariableType(mFuncEa, destVar, ptrTif)) {
                ++mNumApplied;
                DebugPrint("%a: %s::%s applied type\n", mEa, mpService->GetName(),
                           mpTarget->name);
            }
        }

        // For anything else, make an note of it and throw it away
        else {
            qstring estr;
            DebugPrint(
                "%a: %s::%s argument was %s, not global/variable. Could not apply type\n",
                mEa, mpService->GetName(), mpTarget->name, Expr2String(outArg, &estr));
        }
    }
};
