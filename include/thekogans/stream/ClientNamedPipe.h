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
        /// ClientNamedPipe represents the client side of the named pipe. It's responsible
        /// for connecting to the \see{ServerNamedPipe} using it's one and only ctor. Unlike
        /// \see{TCPSocket} clients

        struct _LIB_THEKOGANS_STREAM_DECL ClientNamedPipe : public NamedPipe {
            /// \brief
            /// ClientNamedPipe is a \see{Stream}.
            THEKOGANS_STREAM_DECLARE_STREAM (ClientNamedPipe)

            /// \brief
            /// ctor.
            /// Create a client side named pipe.
            /// \param[in] name Name of pipe to connect to.
            /// \param[in] desiredAccess The requested access to the file or device,
            /// which can be summarized as read, write, both or neither zero).
            /// +------------------+----------------------------+
            /// | Constant         | Generic meaning            |
            /// +------------------+----------------------------+
            /// | GENERIC_ALL      | All possible access rights |
            /// +------------------+----------------------------+
            /// | GENERIC_EXECUTE  | Execute access             |
            /// +------------------+----------------------------+
            /// | GENERIC_READ     | Read access                |
            /// +------------------+----------------------------+
            /// | GENERIC_WRITE    | Write access               |
            /// +------------------+----------------------------+
            /// \param[in] shareMode The requested sharing mode of the file or device,
            /// which can be read, write, both, delete, all of these, or none.
            /// +--------------------+---------------------------------------------------------------------------+
            /// | Value              | Meaning                                                                   |
            /// +--------------------+---------------------------------------------------------------------------+
            /// | 0                  | Prevents subsequent open operations on a file or device if they request   |
            /// | 0x00000000         | delete, read, or write access.                                            |
            /// +--------------------+---------------------------------------------------------------------------+
            /// | FILE_SHARE_DELETE  | Enables subsequent open operations on a file or device to request delete  |
            /// | 0x00000004         | access. Otherwise, no process can open the file or device if it requests  |
            /// |                    | delete access. If this flag is not specified, but the file or device has  |
            /// |                    | been opened for delete access, the function fails. Note Delete access     |
            /// |                    | allows both delete and rename operations.                                 |
            /// +--------------------+---------------------------------------------------------------------------+
            /// | FILE_SHARE_READ    | Enables subsequent open operations on a file or device to request read    |
            /// | 0x00000001         | access. Otherwise, no process can open the file or device if it requests  |
            /// |                    | read access. If this flag is not specified, but the file or device has    |
            /// |                    | been opened for read access, the function fails.                          |
            /// +--------------------+---------------------------------------------------------------------------+
            /// | FILE_SHARE_WRITE   | Enables subsequent open operations on a file or device to request write   |
            /// | 0x00000002         | access. Otherwise, no process can open the file or device if it requests  |
            /// |                    | write access. If this flag is not specified, but the file or device has   |
            /// |                    | been opened for write access or has a file mapping with write access,     |
            /// |                    | the function fails.                                                       |
            /// +--------------------+---------------------------------------------------------------------------+
            /// \param[in] securityAttributes A pointer to a SECURITY_ATTRIBUTES structure that contains two
            /// separate but related data members: an optional security descriptor, and a Boolean value that
            /// determines whether the returned handle can be inherited by child processes.
            /// This parameter can be NULL.
            /// If this parameter is NULL, the handle returned by CreateFile cannot be inherited by any child
            /// processes the application may create and the file or device associated with the returned handle
            /// gets a default security descriptor.
            /// The lpSecurityDescriptor member of the structure specifies a SECURITY_DESCRIPTOR for a file or
            /// device. If this member is NULL, the file or device associated with the returned handle is assigned
            /// a default security descriptor.
            /// CreateFile ignores the lpSecurityDescriptor member when opening an existing file or device, but
            /// continues to use the bInheritHandle member.
            /// The bInheritHandle member of the structure specifies whether the returned handle can be inherited.
            ClientNamedPipe (
                const std::string &name,
                DWORD desiredAccess = GENERIC_READ | GENERIC_WRITE,
                DWORD shareMode = 0,
                LPSECURITY_ATTRIBUTES securityAttributes = 0,
                DWORD creationDisposition = OPEN_EXISTING,
                DWORD flagsAndAttributes = FILE_ATTRIBUTE_NORMAL,
                HANDLE templateFile = 0);

            /// \brief
            /// Wait for a server side instance of the pipe to become available for connecting.
            /// \param[in] name Name of pipe to wait for.
            /// \param[in] timeout How long to wait for connection before giving up.
            /// \return true == An instance of the server pipe with the given name
            /// is available for connecting to.
            static bool WaitForServer (
                const std::string &name,
                DWORD timeout);
        };

    } // namespace stream
} // namespace thekogans

#endif // defined (TOOLCHAIN_OS_Windows)

#endif // !defined (__thekogans_stream_ClientNamedPipe_h)
