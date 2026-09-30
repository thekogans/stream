cmake_minimum_required(VERSION 3.16...3.25)

# ==============================================================================
# 1. Versioning Details & Project Initialization
# ==============================================================================
set(THEKOGANS_STREAM_MAJOR_VERSION 0)
set(THEKOGANS_STREAM_MINOR_VERSION 14)
set(THEKOGANS_STREAM_PATCH_VERSION 0)

# Generate Hex Version String dynamically: (MAJOR << 16) | (MINOR << 8) | PATCH
math(EXPR VERSION_HEX "(${THEKOGANS_STREAM_MAJOR_VERSION} * 65536) + (${THEKOGANS_STREAM_MINOR_VERSION} * 256) + ${THEKOGANS_STREAM_PATCH_VERSION}")
string(HEX ${VERSION_HEX} HEX_STRING)
string(LENGTH "${HEX_STRING}" HEX_LEN)
while(HEX_LEN LESS 8)
    set(HEX_STRING "0${HEX_STRING}")
    string(LENGTH "${HEX_STRING}" HEX_LEN)
endwhile()
set(THEKOGANS_STREAM_VERSION_HEX "0x${HEX_STRING}")

project(thekogans_stream
    VERSION ${THEKOGANS_STREAM_MAJOR_VERSION}.${THEKOGANS_STREAM_MINOR_VERSION}.${THEKOGANS_STREAM_PATCH_VERSION}
    LANGUAGES C CXX)

# ==============================================================================
# 2. Dependency Tracking
# ==============================================================================
# Locate your parent utilities layer. Inherits C++17 rules and include tracks automatically.
find_package(thekogans_util 0.39 REQUIRED)

# Platform-specific tracking dependencies
if(WIN32)
    set(PLATFORM_LIBS Ws2_32 Iphlpapi Advapi32)
elseif(APPLE)
    find_library(CORE_FOUNDATION_FRAMEWORK CoreFoundation REQUIRED)
    find_library(SYSTEM_CONFIGURATION_FRAMEWORK SystemConfiguration REQUIRED)
    set(PLATFORM_LIBS ${CORE_FOUNDATION_FRAMEWORK} ${SYSTEM_CONFIGURATION_FRAMEWORK})
endif()

# ==============================================================================
# 3. Main Target Construction & Processor Definitions
# ==============================================================================
option(BUILD_SHARED_LIBS "Build shared libraries instead of static" ON)
add_library(thekogans_stream)

# Define version macros matching your configuration matrix
target_compile_definitions(thekogans_stream PUBLIC
    THEKOGANS_STREAM_MAJOR_VERSION=${THEKOGANS_STREAM_MAJOR_VERSION}
    THEKOGANS_STREAM_MINOR_VERSION=${THEKOGANS_STREAM_MINOR_VERSION}
    THEKOGANS_STREAM_PATCH_VERSION=${THEKOGANS_STREAM_PATCH_VERSION}
    THEKOGANS_STREAM_VERSION=${THEKOGANS_STREAM_VERSION_HEX})

# Automated Configuration Context Definitions via Generator Expressions
target_compile_definitions(thekogans_stream PUBLIC
    THEKOGANS_STREAM_CONFIG_$<CONFIG>)

target_compile_definitions(thekogans_stream PUBLIC
    $<$<BOOL:${BUILD_SHARED_LIBS}>:THEKOGANS_STREAM_TYPE_Shared>
    $<$<NOT:$<BOOL:${BUILD_SHARED_LIBS}>>:THEKOGANS_STREAM_TYPE_Static>)

if(WIN32)
    target_compile_definitions(thekogans_stream PRIVATE
        _CRT_SECURE_NO_WARNINGS
        _LIB_THEKOGANS_STREAM_BUILD)
endif()

# Bind headers path
target_include_directories(thekogans_stream
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)

# Core Source Units
target_sources(thekogans_stream PRIVATE
    src/Adapters.cpp
    src/Address.cpp
    src/AsyncIoEventQueue.cpp
    src/Overlapped.cpp
    src/Pipe.cpp
    src/Socket.cpp
    src/Stream.cpp
    src/TCPSocket.cpp
    src/UDPSocket.cpp
    src/Version.cpp)

# Conditional platform sources (e.g., Windows NamedPipes)
if(WIN32)
    target_sources(thekogans_stream PRIVATE src/NamedPipe.cpp)
endif()

# ==============================================================================
# 4. Target Linkage Binding
# ==============================================================================
target_link_libraries(thekogans_stream
    PUBLIC
        thekogans::thekogans_util
        ${PLATFORM_LIBS})

# ==============================================================================
# 5. Compiler Suppressions (Synchronized with util options)
# ==============================================================================
set(GCC_NO_WARN "-Wno-unused-parameter" "-Wno-interference-size")
set(MSVC_NO_WARN "/wd4100" "/wd4018")

target_compile_options(thekogans_stream PRIVATE
    "$<$<CXX_COMPILER_ID:GNU>:${GCC_NO_WARN}>"
    "$<$<CXX_COMPILER_ID:MSVC>:${MSVC_NO_WARN}>")

# ==============================================================================
# 6. Installation and Export Architecture
# ==============================================================================
include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

set(STREAM_CMAKE_INSTALL_DIR "${CMAKE_INSTALL_LIBDIR}/cmake/thekogans_stream")

install(TARGETS thekogans_stream
    EXPORT thekogans_stream_targets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

install(EXPORT thekogans_stream_targets
    FILE thekogans_streamTargets.cmake
    NAMESPACE thekogans::
    DESTINATION ${STREAM_CMAKE_INSTALL_DIR})

# Install public headers safely retaining organization boundaries
install(DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.h" PATTERN "*.hpp")

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/thekogans_streamConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/thekogans_streamConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/thekogans_streamConfig.cmake"
    INSTALL_DESTINATION ${STREAM_CMAKE_INSTALL_DIR})

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/thekogans_streamConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/thekogans_streamConfigVersion.cmake"
    DESTINATION ${STREAM_CMAKE_INSTALL_DIR})

# ==============================================================================
# 7. Automated Pkg-Config Generation (.pc File)
# ==============================================================================
set(PC_LIBS_PRIVATE "")
foreach(LIB_ITEM IN LISTS PLATFORM_LIBS)
    set(PC_LIBS_PRIVATE "${PC_LIBS_PRIVATE} -l${LIB_ITEM}")
endforeach()

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/thekogans_stream.pc.in"
    "${CMAKE_CURRENT_BINARY_DIR}/thekogans_stream.pc"
    @ONLY)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/thekogans_stream.pc"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
