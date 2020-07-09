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
 * Copyright (C) 2020  Binarly
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
 * efiAnalysis.h
 *
 */

#include "efiSmmUtils.h"
#include "efiUtils.h"

namespace efiAnalysis {
class efiAnalyzer {
  public:
    vector<json> dataGuids;
    vector<json> allProtocols;
    vector<json> allBootServices;
    vector<json> allRuntimeServices;

    bool findImageHandleX64();
    bool findSystemTableX64();
    bool findBootServicesTablesX64();
    bool findRuntimeServicesTablesX64();
    bool findSmstX64();
    void findOtherBsTablesX64();

    void getProtBootServicesX64();
    void getAllBootServicesX64();
    void getAllRuntimeServicesX64();

    void getProtBootServicesX86();

    void getProtNamesX64();

    void getProtNamesX86();

    void printProtocols();
    void markProtocols();
    void markDataGuids();
    void markLocalGuidsX64();

    func_t *findSwSmiHandler();

    efiAnalyzer();
    ~efiAnalyzer();

  private:
    ea_t base;
    ea_t startAddress = 0;
    ea_t endAddress = 0;
    ea_t mainAddress;
    path guidsJsonPath;
    json bootServices;
    json bootServicesAll;
    json runtimeServicesAll;
    json dbProtocols;
    vector<ea_t> markedProtocols;
};

bool efiAnalyzerMainX64();
bool efiAnalyzerMainX86();
}; // namespace efiAnalysis

void showAllChoosers(efiAnalysis::efiAnalyzer analyzer);
