# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020-2026 Binarly

cmake_minimum_required(VERSION 3.10)

project(efiXloader)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(APPLE)
  # to build Mach-O universal binaries with 2 architectures
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -arch x86_64 -arch arm64")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -arch x86_64 -arch arm64")
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  set(CMAKE_CXX_FLAGS
      "${CMAKE_CXX_FLAGS} -Wno-nullability-completeness -Wno-varargs")
endif()

if(NOT MSVC)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-deprecated-declarations")
  add_compile_options(-fPIC -O3 -flto)
endif()

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/../cmake)

find_package(IdaSdk REQUIRED)

include_directories(${PROJECT_SOURCE_DIR}/../third_party)

file(
  GLOB
  uefitool_src
  "uefitool/common/*.c"
  "uefitool/common/*.cpp"
  "uefitool/common/*.h"
  "uefitool/common/bstrlib/*.c"
  "uefitool/common/bstrlib/*.cpp"
  "uefitool/common/bstrlib/*.h"
  "uefitool/common/digest/sha1.c"
  "uefitool/common/digest/sha256.c"
  "uefitool/common/digest/sha512.c"
  "uefitool/common/digest/sm3.c"
  "uefitool/common/generated/*.cpp"
  "uefitool/common/generated/*.h"
  "uefitool/common/kaitai/*.cpp"
  "uefitool/common/kaitai/*.h"
  "uefitool/common/LZMA/*.c"
  "uefitool/common/LZMA/*.cpp"
  "uefitool/common/LZMA/*.h"
  "uefitool/common/LZMA/SDK/C/*.c"
  "uefitool/common/LZMA/SDK/C/*.cpp"
  "uefitool/common/LZMA/SDK/C/*.h"
  "uefitool/common/Tiano/*.c"
  "uefitool/common/Tiano/*.cpp"
  "uefitool/common/Tiano/*.h"
  "uefitool/common/zlib/*.c"
  "uefitool/common/zlib/*.cpp"
  "uefitool/common/zlib/*.h"
  "uefitool/ffsdumper.cpp"
  "uefitool/ffsdumper.h"
  "uefitool/uefidump.cpp"
  "uefitool/uefidump.h"
  "uefitool/version.h")

# efiXloader sources
file(GLOB efiXloader_src "*.cc" "*.h")

add_ida_loader(efiXloader NOEA32 ${PROJECT_SOURCE_DIR}/efi_loader.cc)

set_ida_target_properties(efiXloader PROPERTIES CXX_STANDARD 17)
ida_target_include_directories(efiXloader PRIVATE ${IdaSdk_INCLUDE_DIRS})

add_ida_library(efiXloader_lib NOEA32 ${efiXloader_src} ${uefitool_src}
                uefitool.cc uefitool.h)
ida_target_link_libraries(efiXloader efiXloader_lib)
