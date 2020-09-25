cmake_minimum_required(VERSION 3.16)

project(efiXloader)

file(
  GLOB
  uefitool_src
  "3rd/uefitool/common/*.h"
  "3rd/uefitool/common/*.c"
  "3rd/uefitool/common/*.cpp"
  "3rd/uefitool/common/LZMA/*.cpp"
  "3rd/uefitool/common/LZMA/*.c"
  "3rd/uefitool/common/LZMA/*.h"
  "3rd/uefitool/common/LZMA/SDK/C/*.c"
  "3rd/uefitool/common/LZMA/SDK/C/*.cpp"
  "3rd/uefitool/common/LZMA/SDK/C/*.h"
  "3rd/uefitool/common/Tiano/*.c"
  "3rd/uefitool/common/Tiano/*.cpp"
  "3rd/uefitool/common/Tiano/*.h"
  "3rd/uefitool/common/bstrlib/*.c"
  "3rd/uefitool/common/bstrlib/*.cpp"
  "3rd/uefitool/common/bstrlib/*.h"
  "3rd/uefitool/common/zlib/*.c"
  "3rd/uefitool/common/zlib/*.cpp"
  "3rd/uefitool/common/zlib/*.h"
  "3rd/uefitool/version.h"
  "3rd/uefitool/ffsdumper.cpp"
  "3rd/uefitool/ffsdumper.h"
  "3rd/uefitool/uefidump.cpp"
  "3rd/uefitool/uefidump.h")

# efiLoader sources
file(GLOB efiloader_src "*.h" "*.c" "*.cpp")

add_library(efiXloader SHARED ${efiloader_src} ${uefitool_src} uefitool.cpp
                              uefitool.h)

set(IDA_SDK ${IdaSdk_ROOT_DIR})

target_include_directories(${CMAKE_PROJECT_NAME} PUBLIC "${IDA_SDK}/include")

if(WIN32)
  target_compile_definitions(${CMAKE_PROJECT_NAME} PUBLIC "__X64__")
  target_compile_definitions(${CMAKE_PROJECT_NAME} PUBLIC "__NT__")
  target_compile_definitions(${CMAKE_PROJECT_NAME} PUBLIC "__EA64__")
  set(IDA_LIB_DIR
      "${IDA_SDK}/lib/x64_win_vc_64"
      CACHE PATH "IDA SDK library path" FORCE)
  target_link_libraries(${CMAKE_PROJECT_NAME} "${IDA_LIB_DIR}/ida.lib"
                        "${IDA_LIB_DIR}/pro.lib")
  target_link_options(${CMAKE_PROJECT_NAME} PUBLIC "/EXPORT:LDSC")
  set_target_properties(${PROJECT_NAME} PROPERTIES OUTPUT_NAME "efiXloader64")
endif()

if(UNIX AND NOT APPLE)
  target_compile_definitions(${CMAKE_PROJECT_NAME} PUBLIC "__X64__")
  target_compile_definitions(${CMAKE_PROJECT_NAME} PUBLIC "__LINUX__")
  target_compile_definitions(${CMAKE_PROJECT_NAME} PUBLIC "__EA64__")
  set(IDA_LIB_DIR
      "${IDA_SDK}/lib/x64_linux_gcc_64"
      CACHE PATH "IDA SDK library path" FORCE)
  target_link_libraries(${CMAKE_PROJECT_NAME} "${IDA_LIB_DIR}/libida64.so"
                        "${IDA_LIB_DIR}/pro.a")
  target_link_options(${CMAKE_PROJECT_NAME} PUBLIC
                      "-Wl,--version-script=${PROJECT_SOURCE_DIR}/exports.def")
  set_target_properties(${PROJECT_NAME} PROPERTIES OUTPUT_NAME "efiXloader64")
endif()

if(APPLE)
  target_compile_definitions(${CMAKE_PROJECT_NAME} PUBLIC "__X64__")
  target_compile_definitions(${CMAKE_PROJECT_NAME} PUBLIC "__MAC__")
  target_compile_definitions(${CMAKE_PROJECT_NAME} PUBLIC "__EA64__")
  set(IDA_LIB_DIR
      "${IDA_SDK}/lib/x64_mac_clang_64"
      CACHE PATH "IDA SDK library path" FORCE)
  target_link_libraries(${CMAKE_PROJECT_NAME} "${IDA_LIB_DIR}/libida64.dylib"
                        "${IDA_LIB_DIR}/pro.a")
  # target_link_options(${CMAKE_PROJECT_NAME} PUBLIC
  # "-Wl,--version-script=${PROJECT_SOURCE_DIR}/exports.def")
  set_target_properties(${PROJECT_NAME} PROPERTIES OUTPUT_NAME "efiXloader64")
endif()
