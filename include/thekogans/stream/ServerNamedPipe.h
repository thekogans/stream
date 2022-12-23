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

#include <memory>
#include "pugixml/pugixml.hpp"
#include "thekogans/stream/Config.h"
#include "thekogans/stream/NamedPipe.h"
#include "thekogans/stream/Address.h"

namespace thekogans {
    namespace stream {

        /// \struct ServerNamedPipe ServerNamedPipe.h thekogans/stream/ServerNamedPipe.h
        ///
        /// \brief
        /// Server side named pipe. Use this class to listen for
        /// connections from \see{ClientNamedPipe} instances. ServerNamedPipe
        /// can be either stream or datagram just like sockets. While
        /// named pipes are very similar to sockets, there is one (at least)
        /// crucial difference. While a listening socket can only be used
        /// to listen for connections, and will return a new socket,
        /// a server named pipe will listen and become the other end of the
        /// connection upon receipt. To that end, if you want to be able
        /// to serve multiple ClientNamedPipes, here is a pattern to use:
        ///
        /// \code{.cpp}
        /// void EventHandler::HandleServerNamedPipeConnection (
        ///         ServerNamedPipe &serverNamedPipe) throw () {
        ///     THEKOGANS_UTIL_TRY {
        ///         // Create a new ServerNamedPipe clone.
        ///         ServerNamedPipe::SharedPtr newServerNamedPipe = serverNamedPipe.Clone ();
        ///         // Add the new ServerNamedPipe to the AsyncIoEventQueue.
        ///         // This will put the newly created named pipe in to
        ///         // listening mode.
        ///         eventQueue.AddStream (*newServerNamedPipe, *this);
        ///     }
        ///     THEKOGANS_UTIL_CATCH_AND_LOG
        /// }
        /// \endcode

        struct _LIB_THEKOGANS_STREAM_DECL ServerNamedPipe :
                public NamedPipe,
                public util::Producer<ServerNamedPipeEvents> {
            /// \brief
            /// ServerNamedPipe participates in the Stream dynamic
            /// discovery and creation.
            THEKOGANS_STREAM_DECLARE_STREAM (ServerNamedPipe)

            enum {
                /// \brief
                /// Default size of receive buffer.
                DEFAULT_BUFFER_SIZE = 32768
            };

        protected:
            /// \brief
            /// Address to listen on.
            Address address;
            /// \brief
            /// Pipe type (Byte/Message).
            PipeType pipeType;
            /// \brief
            /// Size of receive buffer.
            DWORD bufferSize;

        public:
            /// \brief
            /// ctor.
            /// Wrap an OS handle.
            /// \param[in] handle OS stream handle to wrap.
            ServerNamedPipe (THEKOGANS_UTIL_HANDLE handle = THEKOGANS_UTIL_INVALID_HANDLE_VALUE) :
                NamedPipe (handle) {}

        protected:
            /// \brief
            /// Used by \see{AsyncIoEventQueue} to notify the stream that
            /// an overlapped operation has completed successfully.
            /// \param[in] overlapped Overlapped that completed successfully.
            virtual void HandleOverlapped (Overlapped &overlapped) throw ();
        };

    } // namespace stream
} // namespace thekogans

#endif // defined (TOOLCHAIN_OS_Windows)

#endif // !defined (__thekogans_stream_ServerNamedPipe_h)
