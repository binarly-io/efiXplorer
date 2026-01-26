// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2020-2026 Binarly

#pragma once

#include "efi_utils.h"
#include <string>

//-------------------------------------------------------------------------
// vulns chooser
class vulns_chooser_t : public chooser_t {
public:
  eavec_t list;
  json chooser_vulns;

  // this object must be allocated using `new`
  vulns_chooser_t(const char *title, bool ok, json_list_t vulns);

  // function that is used to decide whether a new chooser should be opened or
  // we can use the existing one. The contents of the window are completely
  // determined by its title
  virtual const void *get_obj_id(size_t *len) const {
    *len = strlen(title);
    return title;
  }

  // function that returns number of lines in the list
  virtual size_t idaapi get_count() const { return list.size(); }

  // function that generates the list line
  virtual void idaapi get_row(qstrvec_t *cols, int *icon_,
                              chooser_item_attrs_t *attrs, size_t n) const;

  // function that is called when the user hits `Enter`
  virtual cbret_t idaapi enter(size_t n) {
    if (n < list.size())
      jumpto(list[n]);
    return cbret_t();
  }

protected:
  static const int widths_vulns[];
  static const char *const header_vulns[];

  void build_list(bool ok, json_list_t vulns) {
    size_t n = 0;
    for (auto vuln : vulns) {
      list.push_back(vuln["address"]);
      chooser_vulns[n] = vuln;
      n++;
    }
    ok = true;
  }
};

//-------------------------------------------------------------------------
// GUIDs chooser
class guids_chooser_t : public chooser_t {
protected:
  static const int widths_guids[];
  static const char *const header_guids[];

public:
  eavec_t list;
  json chooser_guids;

  // this object must be allocated using `new`
  guids_chooser_t(const char *title, bool ok, json_list_t guids);

  // function that is used to decide whether a new chooser should be opened or
  // we can use the existing one. The contents of the window are completely
  // determined by its title
  virtual const void *get_obj_id(size_t *len) const {
    *len = strlen(title);
    return title;
  }

  // function that returns number of lines in the list
  virtual size_t idaapi get_count() const { return list.size(); }

  // function that generates the list line
  virtual void idaapi get_row(qstrvec_t *cols, int *icon_,
                              chooser_item_attrs_t *attrs, size_t n) const;

  // function that is called when the user hits `Enter`
  virtual cbret_t idaapi enter(size_t n) {
    if (n < list.size())
      jumpto(list[n]);
    return cbret_t();
  }

protected:
  void build_list(bool ok, json_list_t guids) {
    size_t n = 0;
    for (auto guid : guids) {
      list.push_back(guid["address"]);
      chooser_guids[n] = guid;
      n++;
    }
    ok = true;
  }
};

//-------------------------------------------------------------------------
// protocols chooser
class m_protocols_chooser_t : public chooser_t {
protected:
  static const int widths_protocols[];
  static const char *const header_protocols[];

public:
  eavec_t list;
  json chooser_protocols;
  std::string name_key;

  // this object must be allocated using `new`
  m_protocols_chooser_t(const char *title, bool ok, json_list_t interfaces,
                        std::string name_key);

  // function that is used to decide whether a new chooser should be opened or
  // we can use the existing one. The contents of the window are completely
  // determined by its title
  virtual const void *get_obj_id(size_t *len) const {
    *len = strlen(title);
    return title;
  }

  // function that returns number of lines in the list
  virtual size_t idaapi get_count() const { return list.size(); }

  // function that generates the list line
  virtual void idaapi get_row(qstrvec_t *cols, int *icon_,
                              chooser_item_attrs_t *attrs, size_t n) const;

  // function that is called when the user hits `Enter`
  virtual cbret_t idaapi enter(size_t n) {
    if (n < list.size())
      jumpto(list[n]);
    return cbret_t();
  }

protected:
  void build_list(bool ok, json_list_t protocols) {
    size_t n = 0;
    for (auto protocol : protocols) {
      list.push_back(protocol["xref"]);
      chooser_protocols[n] = protocol;
      n++;
    }
    ok = true;
  }
};

//-------------------------------------------------------------------------
// service chooser (address : service_name)
class services_chooser_t : public chooser_t {
protected:
  static const int widths_s[];
  static const char *const header_s[];

public:
  eavec_t list;
  json chooser_s;

  // this object must be allocated using `new`
  services_chooser_t(const char *title, bool ok, json_list_t services);

  // function that is used to decide whether a new chooser should be opened or
  // we can use the existing one. The contents of the window are completely
  // determined by its title
  virtual const void *get_obj_id(size_t *len) const {
    *len = strlen(title);
    return title;
  }

  // function that returns number of lines in the list
  virtual size_t idaapi get_count() const { return list.size(); }

  // function that generates the list line
  virtual void idaapi get_row(qstrvec_t *cols, int *icon_,
                              chooser_item_attrs_t *attrs, size_t n) const;

  // function that is called when the user hits `Enter`
  virtual cbret_t idaapi enter(size_t n) {
    if (n < list.size())
      jumpto(list[n]);
    return cbret_t();
  }

protected:
  void build_list(bool ok, json_list_t services) {
    size_t n = 0;
    for (auto j_service : services) {
      list.push_back(j_service["address"]);
      chooser_s[n] = j_service;
      n++;
    }
    ok = true;
  }
};

//-------------------------------------------------------------------------
// NVRAM chooser
class nvram_chooser_t : public chooser_t {
protected:
  static const int widths_nvram[];
  static const char *const header_nvram[];

public:
  eavec_t list;
  json chooser_nvram;

  // this object must be allocated using `new`
  nvram_chooser_t(const char *title, bool ok, json_list_t nvrams);

  // function that is used to decide whether a new chooser should be opened or
  // we can use the existing one. The contents of the window are completely
  // determined by its title
  virtual const void *get_obj_id(size_t *len) const {
    *len = strlen(title);
    return title;
  }

  // function that returns number of lines in the list
  virtual size_t idaapi get_count() const { return list.size(); }

  // function that generates the list line
  virtual void idaapi get_row(qstrvec_t *cols, int *icon_,
                              chooser_item_attrs_t *attrs, size_t n) const;

  // function that is called when the user hits `Enter`
  virtual cbret_t idaapi enter(size_t n) {
    if (n < list.size())
      jumpto(list[n]);
    return cbret_t();
  }

protected:
  void build_list(bool ok, json_list_t nvrams) {
    size_t n = 0;
    for (auto nvram : nvrams) {
      list.push_back(nvram["addr"]);
      chooser_nvram[n] = nvram;
      n++;
    }
    ok = true;
  }
};

extern action_desc_t action_load_report;

bool show_nvram(json_list_t nvram, qstring title);
bool show_vulns(json_list_t vulns, qstring title);
bool show_guids(json_list_t guid, qstring title);
bool show_protocols(json_list_t protocols, qstring title);
bool show_ppis(json_list_t protocols, qstring title);
bool show_services(json_list_t services, qstring title);
void attach_action_protocols_deps();
void attach_action_modules_seq();
