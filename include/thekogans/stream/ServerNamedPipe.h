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

#if !defined (__thekogans_stream_ServerNamedPipe_h)
#define __thekogans_stream_ServerNamedPipe_h

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

        struct ServerNamedPipe;

        struct _LIB_THEKOGANS_STREAM_DECL ServerNamedPipeEvents : public virtual util::RefCounted {
            /// \brief
            /// Declare \see{util::RefCounted} pointers.
            THEKOGANS_UTIL_DECLARE_REF_COUNTED_POINTERS (ServerNamedPipeEvents)

            /// \brief
            /// dtor.
            virtual ~ServerNamedPipeEvents () {}

            /// \brief
            /// Called to report a connection on a \see{ServerNamedPipe}.
            /// \param[in] serverNamedPipe \see{ServerNamedPipe} on which the connection occurred.
            virtual void OnServerNamedPipeConnected (
                util::RefCounted::SharedPtr<ServerNamedPipe> serverNamedPipe) throw ();
        }

        /// \struct ServerNamedPipe ServerNamedPipe.h thekogans/stream/ServerNamedPipe.h
        ///
        /// \brief

        struct _LIB_THEKOGANS_STREAM_DECL ServerNamedPipe :
                public NamedPipe,
                public util::Producer<ServerNamedPipeEvents> {
            /// \brief
            /// ServerNamedPipe is a \see{Stream}.
            THEKOGANS_STREAM_DECLARE_STREAM (ServerNamedPipe)

            /// \brief
            /// ctor.
            /// Create a server side named pipe.
            /// https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createnamedpipew
            /// \param[in] name The unique pipe name. This string must have the following form: \\.\pipe\pipename
            /// \param[in] openMode Open mode.
            /// \param[in] pipeMode Pipe mode.
            /// \param[in] maxInstances Maximumum concurrent pipe instances.
            /// \param[in] outBufferSize The number of bytes to reserve for the output buffer.
            /// \param[in] inBufferSize The number of bytes to reserve for the input buffer.
            /// \param[in] defaultTimeOut The default time-out value, in milliseconds, if the WaitNamedPipe
            /// function specifies NMPWAIT_USE_DEFAULT_WAIT. Each instance of a named pipe must specify the
            /// same value.
            /// \param[in] securityAttributes A pointer to a SECURITY_ATTRIBUTES structure that specifies a
            /// security descriptor for the new named pipe and determines whether child processes can inherit
            /// the returned handle. If lpSecurityAttributes is NULL, the named pipe gets a default security
            /// descriptor and the handle cannot be inherited. The ACLs in the default security descriptor for
            /// a named pipe grant full control to the LocalSystem account, administrators, and the creator
            /// owner. They also grant read access to members of the Everyone group and the anonymous account.
            ServerNamedPipe (
                const std::string &name,
                DWORD openMode = PIPE_ACCESS_DUPLEX,
                DWORD pipeMode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE,
                DWORD maxInstances = PIPE_UNLIMITED_INSTANCES,
                DWORD outBufferSize = DEFAULT_BUFFER_LENGTH,
                DWORD inBufferSize = DEFAULT_BUFFER_LENGTH,
                DWORD defaultTimeOut = INFINITE,
                LPSECURITY_ATTRIBUTES securityAttributes = DefaultSecurityAttributes ());

            /// \brief
            /// Listen for an incoming connection.
            void Connect ();

            /// \brief
            /// Disconnect the server end of the \see{NamedPipe}.
            /// \param[in] flushBuffers Call FlushFileBuffers before disconnecting.
            void Disconnect (bool flushBuffers = true);

        protected:
            // Stream
            /// \brief
            /// Used by \see{AsyncIoEventQueue} to notify the stream that
            /// an overlapped operation has completed successfully.
            /// \param[in] overlapped \see{Overlapped} that completed successfully.
            virtual void HandleOverlapped (Overlapped &overlapped) throw () override;

            static LPSECURITY_ATTRIBUTES DefaultSecurityAttributes ();
        };

    } // namespace stream
} // namespace thekogans

#endif // defined (TOOLCHAIN_OS_Windows)

#endif // !defined (__thekogans_stream_NamedPipe_h)
