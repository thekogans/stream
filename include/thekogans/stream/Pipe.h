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
#include "thekogans/util/Types.h"
#include "thekogans/util/Exception.h"
#include "thekogans/stream/Config.h"
#include "thekogans/stream/Stream.h"

namespace thekogans {
    namespace stream {

        /// \struct Pipe Pipe.h thekogans/stream/Pipe.h
        ///
        /// \brief
        /// Pipe wraps up an unnamed pipe. On Windows the pipes are
        /// actually created from named pipes so that we can take
        /// advantage of overlapped (async) io.

        struct AsyncIoEventQueue;
        struct StreamSelector;

        struct _LIB_THEKOGANS_STREAM_DECL Pipe : public Stream {
            /// \brief
            /// Convenient typedef for util::ThreadSafeRefCounted::Ptr<Pipe>.
            typedef util::ThreadSafeRefCounted::Ptr<Pipe> Ptr;

            /// \brief
            /// Pipe has a private heap to help with memory management.
            THEKOGANS_UTIL_DECLARE_HEAP_WITH_LOCK (Pipe, util::SpinLock)

            /// \brief
            /// Read timeout (util::TimeSpec::Zero == no timeout).
            util::TimeSpec readTimeout;
            /// \brief
            /// Write timeout (util::TimeSpec::Zero == no timeout).
            util::TimeSpec writeTimeout;

            /// \brief
            /// ctor. \see{Stream}
            /// Used as input to Pipe::Create.
            /// \param[in] handle OS stream handle to wrap.
            explicit Pipe (THEKOGANS_UTIL_HANDLE handle = THEKOGANS_UTIL_INVALID_HANDLE_VALUE) :
                Stream (handle),
                readTimeout (util::TimeSpec::Zero),
                writeTimeout (util::TimeSpec::Zero) {}

            /// \brief
            /// Create both ends of the pipe.
            /// \param[out] readPipe The reading end of the pipe.
            /// \param[out] writePipe The writing end of the pipe.
            static void Create (
                Pipe &readPipe,
                Pipe &writePipe);

            // Stream
            /// \brief
            /// Read bytes from the stream.
            /// \param[out] buffer Where to place the bytes.
            /// \param[in] count Buffer length.
            /// \return Count of bytes actually placed in the buffer.
            /// NOTE: This api is to be called by blocking
            /// streams only. Async stream will listen for
            /// incoming data, and notify AsyncIoEventSink.
            virtual std::size_t Read (
                void *buffer,
                std::size_t count);
            /// \brief
            /// Write bytes to the stream.
            /// \param[in] buffer Bytes to write.
            /// \param[in] count Buffer length.
            /// \return Count of bytes actually written.
            virtual std::size_t Write (
                const void *buffer,
                std::size_t count);

            /// \brief
            /// Async write a buffer to the stream.
            /// \param[in] buffer Buffer to write.
            virtual void WriteBuffer (util::Buffer::UniquePtr buffer);

            /// \brief
            /// Return read timeout value.
            /// \return Read timeout value.
            virtual util::TimeSpec GetReadTimeout () const {
                return readTimeout;
            }
            /// \brief
            /// Set read timeout.
            /// \param[in] timeSpec Read timeout.
            virtual void SetReadTimeout (const util::TimeSpec &timeSpec);

            /// \brief
            /// Return write timeout value.
            /// \return Write timeout value.
            virtual util::TimeSpec GetWriteTimeout () const {
                return writeTimeout;
            }
            /// \brief
            /// Set write timeout.
            /// \param[in] timeSpec Write timeout.
            virtual void SetWriteTimeout (const util::TimeSpec &timeSpec);

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
            /// AsyncIoEventQueue needs access to SetBlocking.
            friend struct AsyncIoEventQueue;
            /// \brief
            /// StreamSelector needs access to SetBlocking.
            friend struct StreamSelector;
        #endif // defined (TOOLCHAIN_OS_Windows)

            /// \brief
            /// Streams are neither copy constructable, nor assignable.
            THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (Pipe)
        };

    } // namespace stream
} // namespace thekogans

#endif // !defined (__thekogans_stream_Pipe_h)
