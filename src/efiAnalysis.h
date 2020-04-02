#include "efiUtils.h"

namespace efiAnalysis {
class efiAnalyzer {
  public:
    bool findImageHandle();
    bool findSystemTable();
    bool findBootServicesTable();
    bool findRuntimeServicesTable();
    void getBootServices();
    void getProtNames();
    void printProtocols();
    void markProtocols();
    void markDataGuids();
    void dumpInfo();
    efiAnalyzer();
    ~efiAnalyzer();

  private:
    bool valid;
    size_t arch;
    ea_t base;
    ea_t startAddress;
    ea_t endAddress;
    ea_t mainAddress;
    path guidsJsonPath;
    json bootServices;
    json dbProtocols;
    vector<json> allProtocols;
    vector<ea_t> markedProtocols;
    string dumpDir = "efiXplorer-logs";
};

bool efiAnalyzerMain();
}; // namespace efiAnalysis
