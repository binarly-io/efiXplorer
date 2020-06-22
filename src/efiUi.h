#include "efiUtils.h"

//-------------------------------------------------------------------------
// guids chooser
class guids_chooser_t : public chooser_t {
  protected:
    static const int widths_guids[];
    static const char *const header_guids[];

  public:
    /* remember the addresses in this qvector */
    eavec_t list;
    json chooser_guids;

    /* this object must be allocated using `new` */
    guids_chooser_t(const char *title, bool ok, vector<json> guids);

    /* function that is used to decide whether a new chooser should be opened or
     * we can use the existing one. The contents of the window are completely
     * determined by its title */
    virtual const void *get_obj_id(size_t *len) const {
        *len = strlen(title);
        return title;
    }

    /* function that returns number of lines in the list */
    virtual size_t idaapi get_count() const { return list.size(); }

    /* function that generates the list line */
    virtual void idaapi get_row(qstrvec_t *cols, int *icon_,
                                chooser_item_attrs_t *attrs, size_t n) const;

    /* function that is called when the user hits Enter */
    virtual cbret_t idaapi enter(size_t n) {
        if (n < list.size())
            jumpto(list[n]);
        return cbret_t();
    }

  protected:
    void build_list(bool ok, vector<json> guids) {
        /* iterate the array */
        size_t n = 0;
        for (vector<json>::iterator g = guids.begin(); g != guids.end(); ++g) {
            json guid = *g;
            list.push_back(guid["address"]);
            chooser_guids[n] = guid;
            n++;
        }
        ok = true;
    };
};

//-------------------------------------------------------------------------
// protocols chooser
class protocols_chooser_t : public chooser_t {
  protected:
    static const int widths_protocols[];
    static const char *const header_protocols[];

  public:
    /* remember the addresses in this qvector */
    eavec_t list;
    json chooser_protocols;

    /* this object must be allocated using `new` */
    protocols_chooser_t(const char *title, bool ok, vector<json> protocols);

    /* function that is used to decide whether a new chooser should be opened or
     * we can use the existing one. The contents of the window are completely
     * determined by its title */
    virtual const void *get_obj_id(size_t *len) const {
        *len = strlen(title);
        return title;
    }

    /* function that returns number of lines in the list */
    virtual size_t idaapi get_count() const { return list.size(); }

    /* function that generates the list line */
    virtual void idaapi get_row(qstrvec_t *cols, int *icon_,
                                chooser_item_attrs_t *attrs, size_t n) const;

    /* function that is called when the user hits Enter */
    virtual cbret_t idaapi enter(size_t n) {
        if (n < list.size())
            jumpto(list[n]);
        return cbret_t();
    }

  protected:
    void build_list(bool ok, vector<json> protocols) {
        /* iterate the array */
        size_t n = 0;
        for (vector<json>::iterator p = protocols.begin(); p != protocols.end();
             ++p) {
            json protocol = *p;
            list.push_back(protocol["address"]);
            chooser_protocols[n] = protocol;
            n++;
        }
        ok = true;
    };
};

bool guids_show(vector<json> guid);
bool protocols_show(vector<json> protocols);
