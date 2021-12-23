cmake_minimum_required(VERSION 3.7)

project(efiXplorer CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(APPLE)
  # to build Mach-O universal binaries with 2 architectures
  set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} "-fPIC -arch x86_64")
else()
  set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} "-fPIC")
endif()

if(BATCH)
  add_definitions(-DBATCH=1)
  set(BATCH 1)
  message(STATUS "efiXplorer plugin version for idat/idat64 binaries")
endif()

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/../cmake)

find_package(IdaSdk REQUIRED)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/3rd/nlohmann_json)
include_directories(${PROJECT_SOURCE_DIR}/3rd/libfort)

# efiXplorer sources
set(efiXplorer_src
    "efiAnalysis.cpp"
    "efiAnalysis.h"
    "efiDeps.cpp"
    "efiDeps.h"
    "efiGlobal.h"
    "efiGlobal.cpp"
    "efiSmmUtils.cpp"
    "efiSmmUtils.h"
    "efiUi.cpp"
    "efiUi.h"
    "efiUtils.cpp"
    "efiUtils.h"
    "efiXplorer.cpp"
    "efiXplorer.h")

if(HexRaysSdk_ROOT_DIR)
  add_definitions(-DHEX_RAYS=1)
  set(HexRaysSdk_INCLUDE_DIRS ${HexRaysSdk_ROOT_DIR}/include)
  include_directories(${HexRaysSdk_INCLUDE_DIRS})
  list(APPEND efiXplorer_src "efiHexRays.cpp" "efiHexRays.h")
endif()

add_ida_plugin(efiXplorer ${PROJECT_SOURCE_DIR}/efiXplorer.cpp)

set_ida_target_properties(efiXplorer PROPERTIES CXX_STANDARD 17)
ida_target_include_directories(efiXplorer PRIVATE ${IdaSdk_INCLUDE_DIRS})

add_ida_library(efiXplorer_lib ${efiXplorer_src})
ida_target_link_libraries(efiXplorer efiXplorer_lib)
