#include "efiUtils.h"

//-------------------------------------------------------------------------
// non-modal call instruction chooser
// from IDA_SDK/plugins/choose
struct calls_chooser_t : public chooser_t {
  protected:
    static const int widths_[];
    static const char *const header_[];

  public:
    // remember the call instruction addresses in this qvector
    eavec_t list;

    // this object must be allocated using `new`
    calls_chooser_t(const char *title, bool ok, func_item_iterator_t *fii);

    // function that is used to decide whether a new chooser should be opened
    // or we can use the existing one.
    // The contents of the window are completely determined by its title
    virtual const void *get_obj_id(size_t *len) const {
        *len = strlen(title);
        return title;
    }

    // function that returns number of lines in the list
    virtual size_t idaapi get_count() const { return list.size(); }

    // function that generates the list line
    virtual void idaapi get_row(qstrvec_t *cols, int *icon_,
                                chooser_item_attrs_t *attrs, size_t n) const;

    // function that is called when the user hits Enter
    virtual cbret_t idaapi enter(size_t n) {
        if (n < list.size())
            jumpto(list[n]);
        return cbret_t(); // nothing changed
    }

  protected:
    void build_list(bool ok, func_item_iterator_t *fii) {
        insn_t insn;
        while (ok) {
            ea_t ea = fii->current();
            if (decode_insn(&insn, ea) > 0 &&
                is_call_insn(insn)) // a call instruction is found
                list.push_back(ea);
            ok = fii->next_code();
        }
    }
};
