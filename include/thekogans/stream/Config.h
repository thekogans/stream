// Copyright 2011 Boris Kogan (boris@thekogans.net)
//
// This file is part of libthekogans_stream.
//
// libthekogans_stream is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// libthekogans_stream is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with libthekogans_stream. If not, see <http://www.gnu.org/licenses/>.

#if !defined (__thekogans_stream_Config_h)
#define __thekogans_stream_Config_h

#if !defined (__cplusplus)
    #error libthekogans_stream requires C++ compilation (use a .cpp suffix)
#endif // !defined (__cplusplus)

#include "thekogans/util/Environment.h"

#if defined (TOOLCHAIN_OS_Windows)
    #define _LIB_THEKOGANS_STREAM_API __stdcall
    #if defined (THEKOGANS_STREAM_TYPE_Shared)
        #if defined (_LIB_THEKOGANS_STREAM_BUILD)
            #define _LIB_THEKOGANS_STREAM_DECL __declspec (dllexport)
        #else // defined (_LIB_THEKOGANS_STREAM_BUILD)
            #define _LIB_THEKOGANS_STREAM_DECL __declspec (dllimport)
        #endif // defined (_LIB_THEKOGANS_STREAM_BUILD)
    #else // defined (THEKOGANS_STREAM_TYPE_Shared)
        #define _LIB_THEKOGANS_STREAM_DECL
    #endif // defined (THEKOGANS_STREAM_TYPE_Shared)
    #if defined (_MSC_VER)
        #pragma warning (disable: 4251)  // using non-exported as public in exported
        #pragma warning (disable: 4786)
    #endif // defined (_MSC_VER)
    #include "thekogans/util/os/windows/WindowsHeader.h"
    #include <winsock2.h>
    #include <iphlpapi.h>
    #include <ws2tcpip.h>
    #include <mswsock.h>
    #include <mstcpip.h>
    #include <memory.h>
    /// \def
    /// Windows socket handle.
    #define THEKOGANS_STREAM_SOCKET SOCKET
    /// \def
    /// Adds to the portability between Windows and POSIX.
    #define THEKOGANS_STREAM_INVALID_SOCKET INVALID_SOCKET
    /// \def
    /// Adds to the portability between Windows and POSIX.
    #define THEKOGANS_STREAM_SOCKET_ERROR SOCKET_ERROR
    /// \def
    /// Windows error code.
    #define THEKOGANS_STREAM_SOCKET_ERROR_CODE WSAGetLastError ()
#else // defined (TOOLCHAIN_OS_Windows)
    #define _LIB_THEKOGANS_STREAM_API
    #define _LIB_THEKOGANS_STREAM_DECL
    #include <sys/socket.h>
    #include <sys/un.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <fcntl.h>
    #include <errno.h>
    /// \def
    /// POSIX socket handle.
    #define THEKOGANS_STREAM_SOCKET int
    /// \def
    /// Adds to the portability between Windows and POSIX.
    #define THEKOGANS_STREAM_INVALID_SOCKET -1
    /// \def
    /// Adds to the portability between Windows and POSIX.
    #define THEKOGANS_STREAM_SOCKET_ERROR -1
    /// \def
    /// POSIX error code.
    #define THEKOGANS_STREAM_SOCKET_ERROR_CODE errno
#endif // defined (TOOLCHAIN_OS_Windows)

/// \def THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN(type)
/// A convenient macro to suppress copy construction and assignment.
#define THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN(type)\
private:\
    type (const type &);\
    type &operator = (const type &);

/// \def THEKOGANS_STREAM
/// Logging subsystem name.
#define THEKOGANS_STREAM "thekogans_stream"

#endif // !defined (__thekogans_stream_Config_h)
