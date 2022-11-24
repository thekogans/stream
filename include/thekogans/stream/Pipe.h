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

#if !defined (__thekogans_stream_Pipe_h)
#define __thekogans_stream_Pipe_h

#include <cstdio>
#include <memory>
#include <string>
#include "thekogans/util/Environment.h"
#include "thekogans/util/Types.h"
#include "thekogans/util/Exception.h"
#include "thekogans/stream/Config.h"
#include "thekogans/stream/Stream.h"

namespace thekogans {
    namespace stream {

        /// \brief
        /// Forward declaration of \see{StreamSelector}.
        struct StreamSelector;
        /// \brief
        /// Forward declaration of \see{AsyncIoEventQueue}.
        struct AsyncIoEventQueue;

        /// \struct Pipe Pipe.h thekogans/stream/Pipe.h
        ///
        /// \brief
        /// Pipe wraps up an unnamed pipe. On Windows the pipes are
        /// actually created from named pipes so that we can take
        /// advantage of overlapped (async) io.

        struct _LIB_THEKOGANS_STREAM_DECL Pipe : public Stream {
            /// \brief
            /// Declare \see{RefCounted} pointers.
            THEKOGANS_UTIL_DECLARE_REF_COUNTED_POINTERS (Pipe)

            /// \brief
            /// Pipe has a private heap to help with memory management.
            THEKOGANS_UTIL_DECLARE_HEAP_WITH_LOCK (Pipe, util::SpinLock)

            /// \brief
            /// ctor. \see{Stream}
            /// Used as input to Pipe::Create.
            /// \param[in] handle OS stream handle to wrap.
            explicit Pipe (THEKOGANS_UTIL_HANDLE handle = THEKOGANS_UTIL_INVALID_HANDLE_VALUE) :
                Stream (handle) {}

            /// \brief
            /// Create both ends of the pipe.
            /// \param[out] readPipe The reading end of the pipe.
            /// \param[out] writePipe The writing end of the pipe.
            static void Create (
                Pipe &readPipe,
                Pipe &writePipe);

            // Stream
            /// \brief
            /// Write bytes to the stream.
            /// \param[in] buffer Bytes to write.
            /// \param[in] count Buffer length.
            /// \return Count of bytes actually written.
            virtual void Write (
                const void *buffer,
                std::size_t count);

            /// \brief
            /// Async write a buffer to the stream.
            /// \param[in] buffer Buffer to write.
            virtual void WriteBuffer (util::Buffer buffer);

            /// \brief
            /// Return number of bytes available for reading.
            /// \return Number of bytes available for reading.
            std::size_t GetDataAvailable ();

        protected:
            // Stream
            /// \brief
            /// Used by the AsyncIoEventQueue to allow the stream to
            /// initialize itself. When this function is called, the
            /// stream is already async, and \see{Stream::AsyncInfo}
            /// has been created. At this point the stream should do
            /// whatever stream specific initialization it needs to
            /// do.
            virtual void InitAsyncIo ();
        #if defined (TOOLCHAIN_OS_Windows)
            /// \brief
            /// Initiate an overlapped ReadFile.
            void PostAsyncRead ();
            /// \brief
            /// Used by \see{AsyncIoEventQueue} to notify the stream that
            /// an overlapped operation has completed successfully.
            /// \param[in] overlapped \see{Overlapped} that completed successfully.
            virtual void HandleOverlapped (AsyncInfo::Overlapped &overlapped) throw ();
        #else // defined (TOOLCHAIN_OS_Windows)
            /// \brief
            /// Put the pipe in (non-)blocking mode.
            /// \param[in] blocking true = blocking, false = non-blocking
            void SetBlocking (bool blocking);
            /// \brief
            /// Used by AsyncIoEventQueue to notify the stream of
            /// pending io events.
            /// \param[in] event \see{AsyncIoEventQueue} events enum.
            virtual void HandleAsyncEvent (util::ui32 event) throw ();

            /// \brief
            /// StreamSelector needs access to SetBlocking.
            friend struct StreamSelector;
            /// \brief
            /// AsyncIoEventQueue needs access to SetBlocking.
            friend struct AsyncIoEventQueue;
        #endif // defined (TOOLCHAIN_OS_Windows)

            /// \brief
            /// Streams are neither copy constructable, nor assignable.
            THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (Pipe)
        };

    } // namespace stream
} // namespace thekogans

#endif // !defined (__thekogans_stream_Pipe_h)
