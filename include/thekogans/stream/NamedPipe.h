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

#if !defined (__thekogans_stream_NamedPipe_h)
#define __thekogans_stream_NamedPipe_h

#include "thekogans/util/Environment.h"

#if defined (TOOLCHAIN_OS_Windows)

#include <string>
#include "thekogans/util/os/windows/WindowsHeader.h"
#include "thekogans/util/Types.h"
#include "thekogans/util/RefCounted.h"
#include "thekogans/util/Producer.h"
#include "thekogans/stream/Config.h"
#include "thekogans/stream/Overlapped.h"
#include "thekogans/stream/Stream.h"

namespace thekogans {
    namespace stream {

        /// \brief
        /// Forward declaration of \see{NamedPipe}.
        struct NamedPipe;

        /// \struct NamedPipeEvents NamedPipe.h thekogans/stream/NamedPipe.h
        ///
        /// \brief
        /// Subscribe to NamedPipeEvents to receive \see{NamedPipe} event notifications.

        struct _LIB_THEKOGANS_STREAM_DECL NamedPipeEvents {
            /// \brief
            /// dtor.
            virtual ~NamedPipeEvents () {}

            /// \brief
            /// Called to report a connection on a server side \see{NamedPipe}.
            /// \param[in] namedPipe \see{NamedPipe} on which the connection occurred.
            virtual void OnNamedPipeConnected (
                util::RefCounted::SharedPtr<NamedPipe> namedPipe) noexcept {}
        };

        /// \struct NamedPipe NamedPipe.h thekogans/stream/NamedPipe.h
        ///
        /// \brief
        /// NamedPipe wraps the Windows named pipe machinery.

        struct _LIB_THEKOGANS_STREAM_DECL NamedPipe :
                public Stream,
                public util::Producer<NamedPipeEvents> {
            /// \brief
            /// NamedPipe is a \see{Stream}.
            THEKOGANS_STREAM_DECLARE_STREAM (NamedPipe)

            /// \brief
            /// ctor.
            /// Wrap an OS handle.
            /// \param[in] handle OS stream handle to wrap.
            explicit NamedPipe (THEKOGANS_UTIL_HANDLE handle) :
                Stream (handle) {}

            /// \brief
            /// Wait for a server side instance of the pipe to become available for connecting.
            /// \param[in] name Name of pipe to wait for.
            /// \param[in] timeout How long to wait for connection before giving up.
            /// \return true == An instance of the server pipe with the given name
            /// is available for connecting to.
            static bool Wait (
                const std::string &name,
                DWORD timeout = INFINITE);

            /// \brief
            /// Create a client side named pipe.
            /// \param[in] name Name of pipe to connect to.
            /// NOTE: It should have the following format; \\.\pipe\'pipe name'
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
            /// NOTE: Client side NamedPipe connect synchronously. Therefore, when this call returns the client
            /// has successfuly connected. From here on out all operations are asynchronous. To avoid potential
            /// delays use Wait above (bofore calling this method) to make sure an instance of the server end
            /// of the pipe is available.
            /// \return Client side named pipe already connected ready to send/receive data.
            static SharedPtr CreateClientNamedPipe (
                const std::string &name,
                DWORD desiredAccess = GENERIC_READ | GENERIC_WRITE,
                DWORD shareMode = 0,
                LPSECURITY_ATTRIBUTES securityAttributes = 0,
                DWORD creationDisposition = OPEN_EXISTING,
                DWORD flagsAndAttributes = FILE_ATTRIBUTE_NORMAL,
                HANDLE templateFile = 0);

            /// \brief
            /// Create a server side named pipe.
            /// https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createnamedpipew
            /// \param[in] name The unique pipe name. This string must have the following form: \\.\pipe\pipename
            /// \param[in] openMode Open mode.
            /// \param[in] pipeMode Pipe mode.
            /// \param[in] maxInstances Maximumum concurrent pipe instances.
            /// \param[in] outBufferSize The number of bytes to reserve for the output buffer.
            /// \param[in] inBufferSize The number of bytes to reserve for the input buffer.
            /// \param[in] defaultTimeOut The default time-out value, in milliseconds, if the Wait
            /// function specifies NMPWAIT_USE_DEFAULT_WAIT. Each instance of a named pipe must specify the
            /// same value.
            /// \param[in] securityAttributes A pointer to a SECURITY_ATTRIBUTES structure that specifies a
            /// security descriptor for the new named pipe and determines whether child processes can inherit
            /// the returned handle. If lpSecurityAttributes is NULL, the named pipe gets a default security
            /// descriptor and the handle cannot be inherited. The ACLs in the default security descriptor for
            /// a named pipe grant full control to the LocalSystem account, administrators, and the creator
            /// owner. They also grant read access to members of the Everyone group and the anonymous account.
            /// NOTE: When this method returns the pipe is created and is asynchronous. Use Connect below to
            /// start waiting on incomming connection requests.
            /// \return Server side named pipe ready to staart receiving connections.
            static SharedPtr CreateServerNamedPipe (
                const std::string &name,
                DWORD openMode = PIPE_ACCESS_DUPLEX,
                DWORD pipeMode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE,
                DWORD maxInstances = PIPE_UNLIMITED_INSTANCES,
                DWORD outBufferSize = DEFAULT_BUFFER_LENGTH,
                DWORD inBufferSize = DEFAULT_BUFFER_LENGTH,
                DWORD defaultTimeOut = INFINITE,
                LPSECURITY_ATTRIBUTES securityAttributes = DefaultSecurityAttributes ());

            // Stream
            /// \brief
            /// Read bytes from the stream.
            /// \param[in] bufferLength Buffer length for async WSARecv[From | Msg].
            virtual void Read (std::size_t bufferLength = DEFAULT_BUFFER_LENGTH) override;
            /// \brief
            /// Write buffer the stream.
            /// \param[in] buffer Buffer to write.
            virtual void Write (util::Buffer::SharedPtr buffer) override;

            /// \brief
            /// Set pipe mode (PIPE_TYPE_BYTE | PIPE_READMODE_BYTE).
            /// \param[in] pipeMode New pipe mode.
            void SetMode (DWORD pipeMode);

            /// \brief
            /// Listen for an incoming connection.
            /// Use this method in conjunction with CreateServerNamedPipe above.
            void Connect ();

            /// \brief
            /// Disconnect the server end of the \see{NamedPipe}.
            void Disconnect ();

            /// \brief
            /// Call FlushFileBuffers.
            void FlushBuffers ();

        protected:
            /// \brief
            /// Create default pipe security attributes.
            /// \return Default security attributes.
            static LPSECURITY_ATTRIBUTES DefaultSecurityAttributes ();
        };

    } // namespace stream
} // namespace thekogans

#endif // defined (TOOLCHAIN_OS_Windows)

#endif // !defined (__thekogans_stream_NamedPipe_h)
