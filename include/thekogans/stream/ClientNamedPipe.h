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

#if !defined (__thekogans_stream_ClientNamedPipe_h)
#define __thekogans_stream_ClientNamedPipe_h

#include "thekogans/util/Environment.h"

#if defined (TOOLCHAIN_OS_Windows)

#if !defined (_WINDOWS_)
    #if !defined (WIN32_LEAN_AND_MEAN)
        #define WIN32_LEAN_AND_MEAN
    #endif // !defined (WIN32_LEAN_AND_MEAN)
    #if !defined (NOMINMAX)
        #define NOMINMAX
    #endif // !defined (NOMINMAX)
    #include <windows.h>
#endif // !defined (_WINDOWS_)
#include "thekogans/stream/Config.h"
#include "thekogans/stream/NamedPipe.h"

namespace thekogans {
    namespace stream {

        /// \struct ClientNamedPipe ClientNamedPipe.h thekogans/stream/ClientNamedPipe.h
        ///
        /// \brief

        struct _LIB_THEKOGANS_STREAM_DECL ClientNamedPipe : public NamedPipe {
            /// \brief
            /// NamedPipe is a \see{Stream}.
            THEKOGANS_STREAM_DECLARE_STREAM (ClientNamedPipe)

            /// \brief
            /// ctor.
            /// Create a client side named pipe.
            /// \param[in] name Name of pipe to connect to..
            ClientNamedPipe (
                LPCWSTR name,
                DWORD desiredAccess = GENERIC_READ | GENERIC_WRITE,
                DWORD shareMode = 0,
                LPSECURITY_ATTRIBUTES securityAttributes = 0,
                DWORD creationDisposition = OPEN_EXISTING,
                DWORD flagsAndAttributes = FILE_ATTRIBUTE_NORMAL,
                HANDLE templateFile = 0);

            /// \brief
            /// Wait for a server side instance of the pipe to become available for connecting.
            /// \param[in] timeout How long to wait for connection before giving up.
            static bool WaitForServer (
                LPCWSTR name,
                DWORD timeout);
        };

    } // namespace stream
} // namespace thekogans

#endif // defined (TOOLCHAIN_OS_Windows)

#endif // !defined (__thekogans_stream_ClientNamedPipe_h)
