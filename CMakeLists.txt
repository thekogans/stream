if(WIN32)
    add_definitions(
        -DTOOLCHAIN_OS_Windows
        -D_LIB_THEKOGANS_STREAM_BUILD)
    remove_definitions(
        -DUNICODE
        -D_UNICODE)
endif()

if(APPLE)
    add_definitions(-DTOOLCHAIN_OS_OSX)
endif()

# TODO (rbosa): Please automate the pickup of the version numbers from 'thekogans_make.xml'
add_definitions(
    -DTOOLCHAIN_ARCH_x86_64
    -DTHEKOGANS_STREAM_MAJOR_VERSION=0
    -DTHEKOGANS_STREAM_MINOR_VERSION=8
    -DTHEKOGANS_STREAM_PATCH_VERSION=9)

if(KRAGLE_DEPS)
    add_definitions(-DTHEKOGANS_STREAM_HAVE_OPENSSL)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_definitions(-DTOOLCHAIN_CONFIG_Debug)
else()
    add_definitions(-DTOOLCHAIN_CONFIG_Release)
endif()

file(GLOB_RECURSE HEADERS "include/thekogans/stream/*.h")
set(SOURCES
    src/Adapters.cpp
    src/Address.cpp
    src/AsyncIoEventQueue.cpp
    src/AsyncIoEventSink.cpp
    src/ClientSecureTCPSocket.cpp
    src/ClientSecureUDPSocket.cpp
    src/ClientTCPSocket.cpp
    src/ClientUDPSocket.cpp
    src/MsgHdr.cpp
    src/OpenSSLUtils.cpp
    src/OpenSSLUtilsEx.cpp
    src/Pipe.cpp
    src/SecureTCPSocket.cpp
    src/SecureUDPSocket.cpp
    src/ServerSecureTCPSocket.cpp
    src/ServerSecureUDPSocket.cpp
    src/ServerTCPSocket.cpp
    src/ServerUDPSocket.cpp
    src/Socket.cpp
    src/Stream.cpp
    src/StreamSelector.cpp
    src/TCPSocket.cpp
    src/UDPSocket.cpp
    src/Version.cpp)

if(WIN32)
    set(SOURCES ${SOURCES}
        src/ClientNamedPipe.cpp
        src/NamedPipe.cpp
        src/ServerNamedPipe.cpp
        src/StreamLogger.cpp)
endif()


add_library(thekogans_stream ${HEADERS} ${SOURCES})

if(WIN32)
    target_link_libraries(thekogans_stream WS2_32)
endif()

# Link against the dependencies defined by Kragle, if this library is used in kragle
# You might want to setup your own linkage for your project...
if(KRAGLE_DEPS)
    target_compile_definitions(thekogans_stream PUBLIC
        -DTHEKOGANS_STREAM_HAVE_OPENSSL)

    target_link_libraries(thekogans_stream
        thekogans_util
        openssl_lib
        zlib_lib)
endif()

target_include_directories(thekogans_stream PUBLIC include)
