/* All of this stuff should compile with no warnings or errors. However, it's
   currently an incomplete port of my IDAPython version. What needs to happen:

   * I need to be able to get the name of a protocol GUID, either by address,
     or by raw byte values of the GUID. I can generate addresses that I think
     are GUIDs, no problem.

   * It's not clear how to best integrate this functionality with the rest of
     the plugin. As as right-click Hex-Rays menu item? To be able to be applied
     to all functions in the database? To be able to be applied to any function
     specified by address?

   * It's not tested, at all. I haven't even executed it. That's okay, because
     the rest of the code contains no references to this functionality. It is
     dead code that will never be executed in the present state of affairs. But
     obviously, before it's integrated as user functionality, that will need to
     change.
*/

#include "efiHexRays.h"

// Not used
uint32 GetOrdinalByName(const char *name) {
    import_type(get_idati(), -1, name);
    tinfo_t tif;
    if (!tif.get_named_type(get_idati(), name, BTF_STRUCT)) {
        msg("[E] Could not get type named %s\n", name);
        return 0;
    }
    return tif.get_ordinal();
}

// Used by the next function. Given a name, import the structure and retrieve
// its tinfo_t.
bool GetNamedType(const char *name, tinfo_t &tifOut) {
    import_type(get_idati(), -1, name);
    tinfo_t tif;
    if (!tif.get_named_type(get_idati(), name, BTF_STRUCT))
        return false;
    tifOut = tif;
    return true;
}

// Given a name, import the structure and retrieve a tinfo_t specifying a
// pointer to that type.
bool GetPointerToNamedType(const char *name, tinfo_t &tifOut) {
    if (!GetNamedType(name, tifOut))
        return false;
    tinfo_t ptrTif;
    ptrTif.create_ptr(tifOut);
    tifOut = ptrTif;
    return true;
}

// Given a tinfo_t specifying a user-defined type (UDT), look up the specified
// field by its name, and retrieve its offset.
bool OffsetOf(tinfo_t tif, const char *name, unsigned int *offset) {
    // Get the udt details
    udt_type_data_t udt;
    if (!tif.get_udt_details(&udt)) {
        qstring str;
        tif.get_type_name(&str);
        msg("[E] Could not retrieve udt_type_data_t for %s\n", str.c_str());
        return false;
    }

    // Find the udt member
    udt_member_t udm;
    udm.name = name;
    int fIdx = tif.find_udt_member(&udm, STRMEM_NAME);
    if (fIdx < 0) {
        qstring tstr;
        tif.get_type_name(&tstr);
        msg("[E] Could not find UDT member %s::%s\n", tstr.c_str(), name);
        return false;
    }

    // Get the offset of the field
    *offset = static_cast<unsigned int>(udt.at(fIdx).offset >> 3ULL);
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
bool IsPODArray(tinfo_t tif, unsigned int ptrDepth = 0) {
    // If it's not an array, we're done
    if (!tif.is_array())
        return false;

    qstring tstr;

    // If it is an array, we should be able to get its array details.
    array_type_data_t atd;
    if (!tif.get_array_details(&atd)) {
        tif.get_type_name(&tstr);
        msg("[E] %s: can't get array details, despite being an array\n", tstr.c_str());
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
        msg("[I] IsPodArray[%d]: elem_type = %s, b1 = %d, b2 = %d\n", iDepth,
            tstr.c_str(), b1, b2);

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
const char *Expr2String(cexpr_t *e, qstring *out) {
    e->print1(out, NULL);
    tag_remove(out);
    return out->c_str();
}

// Utility function to set a Hex-Rays variable type
bool SetHexRaysVariableType(ea_t funcEa, lvar_t &ll, tinfo_t tif) {
    lvar_saved_info_t lsi;
    lsi.ll = ll;
    lsi.type = tif;
    if (!modify_user_lvar_info(funcEa, MLI_TYPE, lsi)) {
        msg("[E] %a: could not modify lvar type for %s\n", funcEa, ll.name.c_str());
        return false;
    }
    return true;
}
