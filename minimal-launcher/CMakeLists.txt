cmake_minimum_required(VERSION 3.20)
project(ZClientMinimalLauncher LANGUAGES CXX)
include(CTest)

option(ZCLIENT_INJECTOR32_ONLY
  "Build only the native Win32 initial-process injector" OFF)

if(ZCLIENT_INJECTOR32_ONLY)
  if(NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
    message(FATAL_ERROR
      "ZCLIENT_INJECTOR32_ONLY requires a Win32 (32-bit) CMake generator")
  endif()

  add_executable(zclient_injector32
    src/common.cpp
    src/injector32_main.cpp)
  target_compile_features(zclient_injector32 PRIVATE cxx_std_20)
  target_compile_definitions(zclient_injector32 PRIVATE
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX
    _ALLOW_COMPILER_AND_STL_VERSION_MISMATCH)
  target_link_libraries(zclient_injector32 PRIVATE ws2_32)
  if(MSVC)
    target_compile_options(zclient_injector32 PRIVATE /W4 /permissive- /EHsc)
  else()
    target_compile_options(zclient_injector32 PRIVATE -Wall -Wextra -Wpedantic)
  endif()
  return()
endif()

add_executable(zclient_minimal_launcher
  src/bf3_launch.cpp
  src/common.cpp
  src/config.cpp
  src/license_server.cpp
  src/lsx_server.cpp
  src/main.cpp
  src/manual_map.cpp
  src/pe_architecture.cpp
  src/zbackend_client.cpp)
add_library(zclient_lsx_shim SHARED
  src/common.cpp
  src/lsx_shim.cpp
  src/lsx_server.cpp)
set_target_properties(zclient_lsx_shim PROPERTIES
  PREFIX ""
  OUTPUT_NAME "ZClient.LsxShim64")
add_dependencies(zclient_minimal_launcher zclient_lsx_shim)
add_executable(lsx_shim_test src/lsx_shim_test.cpp)
add_dependencies(lsx_shim_test zclient_lsx_shim)
add_executable(bf3_launch_test
  src/bf3_launch.cpp
  src/bf3_launch_test.cpp)
add_executable(pe_architecture_test
  src/pe_architecture.cpp
  src/pe_architecture_test.cpp)
add_executable(license_server_test
  src/license_server.cpp
  src/license_server_test.cpp)
target_compile_features(zclient_minimal_launcher PRIVATE cxx_std_20)
target_compile_features(zclient_lsx_shim PRIVATE cxx_std_20)
target_compile_features(lsx_shim_test PRIVATE cxx_std_20)
target_compile_features(bf3_launch_test PRIVATE cxx_std_20)
target_compile_features(pe_architecture_test PRIVATE cxx_std_20)
target_compile_features(license_server_test PRIVATE cxx_std_20)
foreach(target zclient_minimal_launcher zclient_lsx_shim lsx_shim_test bf3_launch_test pe_architecture_test license_server_test)
  target_compile_definitions(${target} PRIVATE
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX
    _ALLOW_COMPILER_AND_STL_VERSION_MISMATCH)
endforeach()
target_link_libraries(zclient_minimal_launcher PRIVATE ws2_32 bcrypt)
target_link_libraries(zclient_lsx_shim PRIVATE ws2_32 bcrypt)
target_link_libraries(lsx_shim_test PRIVATE ws2_32 iphlpapi)
target_link_libraries(license_server_test PRIVATE ws2_32)

if(MSVC)
  target_compile_options(zclient_minimal_launcher PRIVATE /W4 /permissive- /EHsc)
  target_compile_options(zclient_lsx_shim PRIVATE /W4 /permissive- /EHsc)
  target_compile_options(lsx_shim_test PRIVATE /W4 /permissive- /EHsc)
  target_compile_options(bf3_launch_test PRIVATE /W4 /permissive- /EHsc)
  target_compile_options(pe_architecture_test PRIVATE /W4 /permissive- /EHsc)
  target_compile_options(license_server_test PRIVATE /W4 /permissive- /EHsc)
else()
  target_compile_options(zclient_minimal_launcher PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_options(zclient_lsx_shim PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_options(lsx_shim_test PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_options(bf3_launch_test PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_options(pe_architecture_test PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_options(license_server_test PRIVATE -Wall -Wextra -Wpedantic)
endif()

# The launcher is native x64, but a same-architecture helper is required to
# resolve Win32 imports and manipulate the initial thread context of PE32
# games. Build that small helper in an isolated Win32 CMake tree and publish it
# next to the launcher just like the LSX shim.
include(ExternalProject)
set(ZCLIENT_INJECTOR32_BUILD_DIR
  "${CMAKE_CURRENT_BINARY_DIR}/injector32-build")
ExternalProject_Add(zclient_injector32_build
  SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}"
  BINARY_DIR "${ZCLIENT_INJECTOR32_BUILD_DIR}"
  CMAKE_GENERATOR "Visual Studio 17 2022"
  CMAKE_GENERATOR_PLATFORM Win32
  CMAKE_ARGS
    -DZCLIENT_INJECTOR32_ONLY=ON
    -DCMAKE_CONFIGURATION_TYPES=Release
  BUILD_COMMAND
    "${CMAKE_COMMAND}" --build <BINARY_DIR> --config Release
    --target zclient_injector32
  INSTALL_COMMAND ""
  BUILD_ALWAYS TRUE
  BUILD_BYPRODUCTS
    "${ZCLIENT_INJECTOR32_BUILD_DIR}/Release/zclient_injector32.exe")
add_custom_target(zclient_injector32_publish ALL
  COMMAND "${CMAKE_COMMAND}" -E copy_if_different
    "${ZCLIENT_INJECTOR32_BUILD_DIR}/Release/zclient_injector32.exe"
    "$<TARGET_FILE_DIR:zclient_minimal_launcher>/zclient_injector32.exe"
  DEPENDS zclient_injector32_build
  VERBATIM)
add_dependencies(zclient_minimal_launcher zclient_injector32_publish)

add_test(NAME lsx_shim_redirect COMMAND lsx_shim_test)
add_test(NAME bf3_launch_arguments COMMAND bf3_launch_test)
add_test(NAME pe_architecture COMMAND pe_architecture_test)
add_test(NAME license_server_replay COMMAND license_server_test)
