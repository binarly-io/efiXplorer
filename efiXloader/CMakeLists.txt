cmake_minimum_required(VERSION 3.10)

project(efiXloader)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(APPLE)
  # to build Mach-O universal binaries with 2 architectures
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC -arch x86_64 -arch arm64")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC -arch x86_64 -arch arm64")
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  set(CMAKE_CXX_FLAGS
      "${CMAKE_CXX_FLAGS} -Wno-nullability-completeness -Wno-varargs")
endif()

if(NOT MSVC)
  add_compile_options(-fPIC -O3 -flto)
endif()

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/../cmake)

find_package(IdaSdk REQUIRED)

include_directories(${PROJECT_SOURCE_DIR}/../efiXplorer/3rd/nlohmann_json)

file(
  GLOB
  uefitool_src
  "3rd/uefitool/common/*.c"
  "3rd/uefitool/common/*.cpp"
  "3rd/uefitool/common/*.h"
  "3rd/uefitool/common/bstrlib/*.c"
  "3rd/uefitool/common/bstrlib/*.cpp"
  "3rd/uefitool/common/bstrlib/*.h"
  "3rd/uefitool/common/digest/sha1.c"
  "3rd/uefitool/common/digest/sha256.c"
  "3rd/uefitool/common/digest/sha512.c"
  "3rd/uefitool/common/digest/sm3.c"
  "3rd/uefitool/common/generated/*.cpp"
  "3rd/uefitool/common/generated/*.h"
  "3rd/uefitool/common/kaitai/*.cpp"
  "3rd/uefitool/common/kaitai/*.h"
  "3rd/uefitool/common/LZMA/*.c"
  "3rd/uefitool/common/LZMA/*.cpp"
  "3rd/uefitool/common/LZMA/*.h"
  "3rd/uefitool/common/LZMA/SDK/C/*.c"
  "3rd/uefitool/common/LZMA/SDK/C/*.cpp"
  "3rd/uefitool/common/LZMA/SDK/C/*.h"
  "3rd/uefitool/common/Tiano/*.c"
  "3rd/uefitool/common/Tiano/*.cpp"
  "3rd/uefitool/common/Tiano/*.h"
  "3rd/uefitool/common/zlib/*.c"
  "3rd/uefitool/common/zlib/*.cpp"
  "3rd/uefitool/common/zlib/*.h"
  "3rd/uefitool/ffsdumper.cpp"
  "3rd/uefitool/ffsdumper.h"
  "3rd/uefitool/uefidump.cpp"
  "3rd/uefitool/uefidump.h"
  "3rd/uefitool/version.h")

# efiLoader sources
file(GLOB efiloader_src "*.cc" "*.h")

add_ida_loader(efiXloader NOEA32 ${PROJECT_SOURCE_DIR}/efi_loader.cc)

set_ida_target_properties(efiXloader PROPERTIES CXX_STANDARD 17)
ida_target_include_directories(efiXloader PRIVATE ${IdaSdk_INCLUDE_DIRS})

add_ida_library(efiXloader_lib NOEA32 ${efiloader_src} ${uefitool_src}
                uefitool.cc uefitool.h)
ida_target_link_libraries(efiXloader efiXloader_lib)
