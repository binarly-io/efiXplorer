cmake_minimum_required(VERSION 3.15)
project(efiXplorer)

set(CMAKE_CXX_STANDARD 14)

include_directories(.)

add_executable(efiXplorer
        efiProtocolAnalysis.cpp
        efiProtocolAnalysis.h
        efiProtocolDependecyBrowser.cpp
        efiProtocolDependecyBrowser.h
        efiProtocolExplorer.cpp
        efiProtocolExplorer.h
        efiProtocolGraph.cpp
        efiProtocolGraph.h
        efiSmiHelper.cpp
        efiSmiHelper.h
        efiXplorer.cpp
        efiXplorer.h efiXplorerIDA.cpp efiXplorerIDA.h efiXplorerHexRays.cpp efiXplorerHexRays.h efiEmulatorOptionRom.cpp efiEmulatorOptionRom.h efiEmulatorDxe.cpp efiEmulatorDxe.h)
