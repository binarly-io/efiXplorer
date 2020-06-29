/* efiAnalysis.h
 * This file is part of efiXplorer
 */

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
    ea_t findBootServicesTableX64();
    ea_t findRuntimeServicesTableX64();

    void getProtBootServicesX64();
    void getAllBootServicesX64();
    void getAllRuntimeServicesX64();

    void getProtBootServicesX86();

    void getProtNamesX64();

    void getProtNamesX86();

    void printProtocols();
    void markProtocols();
    void markDataGuids();

    bool findSmmCallout();

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
