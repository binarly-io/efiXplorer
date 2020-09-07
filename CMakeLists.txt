cmake_minimum_required(VERSION 3.7)

project(efiXplorer CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} -fPIC)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

find_package(IdaSdk REQUIRED)

if(MSVC)
  foreach(flag_var
          CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE
          CMAKE_CXX_FLAGS_MINSIZEREL CMAKE_CXX_FLAGS_RELWITHDEBINFO)
    if(${flag_var} MATCHES "/MD")
      string(REGEX REPLACE "/MD" "/MT" ${flag_var} "${${flag_var}}")
    endif()
    if(${flag_var} MATCHES "/MDd")
      string(REGEX REPLACE "/MDd" "/MTd" ${flag_var} "${${flag_var}}")
    endif()
  endforeach()
endif()

include_directories(${PROJECT_SOURCE_DIR}/src)
include_directories(${PROJECT_SOURCE_DIR}/src/thirdparty/nlohmann_json)
include_directories(${PROJECT_SOURCE_DIR}/src/thirdparty/libfort)

add_ida_plugin(efiXplorer ${PROJECT_SOURCE_DIR}/src/efiXplorer.cpp)

set_ida_target_properties(efiXplorer PROPERTIES CXX_STANDARD 17)
ida_target_include_directories(efiXplorer PRIVATE ${IdaSdk_INCLUDE_DIRS})

add_ida_library(efiAnalysis ${PROJECT_SOURCE_DIR}/src/efiAnalysis.cpp)
ida_target_link_libraries(efiXplorer efiAnalysis)

add_ida_library(efiUtils ${PROJECT_SOURCE_DIR}/src/efiUtils.cpp)
ida_target_link_libraries(efiXplorer efiUtils)

add_ida_library(efiSmmUtils ${PROJECT_SOURCE_DIR}/src/efiSmmUtils.cpp)
ida_target_link_libraries(efiXplorer efiSmmUtils)

# add_ida_library(efiHexRays ${PROJECT_SOURCE_DIR}/src/efiHexRays.cpp)
# ida_target_link_libraries(efiXplorer efiHexRays)

add_ida_library(efiUi ${PROJECT_SOURCE_DIR}/src/efiUi.cpp)
ida_target_link_libraries(efiXplorer efiUi)

add_ida_library(fort ${PROJECT_SOURCE_DIR}/src/thirdparty/libfort/fort.cpp)
ida_target_link_libraries(efiXplorer fort)
