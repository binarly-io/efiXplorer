#include "efiUtils.h"

namespace efiAnalysis {
class efiAnalyzer {
  public:
    bool findSystemTable();
    bool findBootServicesTable();
    bool findRuntimeServicesTable();
    void getProtocols();
    void getProtNames();
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
    json allProtocols;
    json dataProtocols;
    json propProtocols;
};

bool efiAnalyzerMain();
}; // namespace efiAnalysis
