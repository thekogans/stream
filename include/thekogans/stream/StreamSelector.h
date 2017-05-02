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

#if !defined (__thekogans_stream_StreamSelector_h)
#define __thekogans_stream_StreamSelector_h

#if defined (TOOLCHAIN_OS_Windows)
    #if !defined (_WINDOWS_)
        #if !defined (WIN32_LEAN_AND_MEAN)
            #define WIN32_LEAN_AND_MEAN
        #endif // !defined (WIN32_LEAN_AND_MEAN)
        #if !defined (NOMINMAX)
            #define NOMINMAX
        #endif // !defined (NOMINMAX)
    #endif // !defined (_WINDOWS_)
    #include <winsock2.h>
#else // defined (TOOLCHAIN_OS_Windows)
    #include <sys/select.h>
#endif // defined (TOOLCHAIN_OS_Windows)
#include "thekogans/util/TimeSpec.h"
#include "thekogans/stream/Config.h"
#if defined (TOOLCHAIN_OS_Windows)
    #include "thekogans/stream/UDPSocket.h"
    #include "thekogans/stream/ClientUDPSocket.h"
#else // defined (TOOLCHAIN_OS_Windows)
    #include "thekogans/stream/Pipe.h"
#endif // defined (TOOLCHAIN_OS_Windows)
#include "thekogans/stream/Stream.h"

namespace thekogans {
    namespace stream {

        /// \struct StreamSelector StreamSelector.h thekogans/stream/StreamSelector.h
        ///
        /// \brief
        /// StreamSelector is a very thin wrapper around the system select call. Both
        /// timed and indefinite wait methods are provided. StreamSelector implements a
        /// self-pipe trick to allow you to call Break from other threads to break out
        /// of the wait cycle. If you need async streams, it is highly recommended that
        /// you consider using \see{AsyncIoEventQueue} as it's optimized to use the best
        /// available facilities on each platform. Also, on Windows, StreamSelector can
        /// only be used with \see{Socket} and it's derivatives. That said, there are
        /// situations where StreamSelector is more than adequate.

        struct _LIB_THEKOGANS_STREAM_DECL StreamSelector {
        private:
            /// \brief
            /// Set of streams listening for data.
            fd_set readSet;
            /// \brief
            /// Set of streams waiting for write buffers to become available.
            fd_set writeSet;
            // Use the self-pipe trick to allow Break(ing) out of
            // Select.
        #if defined (TOOLCHAIN_OS_Windows)
            /// \brief
            /// Listening end of the self-pipe.
            UDPSocket readPipe;
            /// \brief
            /// Writing end of the self-pipe.
            ClientUDPSocket writePipe;
        #else // defined (TOOLCHAIN_OS_Windows)
            /// \brief
            /// Listening end of the self-pipe.
            Pipe readPipe;
            /// \brief
            /// Writing end of the self-pipe.
            Pipe writePipe;
        #endif // defined (TOOLCHAIN_OS_Windows)

        public:
            /// \brief
            /// ctor.
            StreamSelector ();

            /// \brief
            /// Clear the read and write sets.
            void Clear ();

            /// \brief
            /// Add a raw handle to the read set.
            /// \param[in] handle Raw handle to add.
            void AddHandleForReading (THEKOGANS_UTIL_HANDLE handle);
            /// \brief
            /// Add a stream (it's handle) to the read set.
            /// \param[in] stream Stream to add.
            inline void AddStreamForReading (const Stream &stream) {
                AddHandleForReading (stream.handle);
            }
            /// \brief
            /// Add a raw handle to the write set.
            /// \param[in] handle Raw handle to add.
            void AddHandleForWriting (THEKOGANS_UTIL_HANDLE handle);
            /// \brief
            /// Add a stream (it's handle) to the write set.
            /// \param[in] stream Stream to add.
            inline void AddStreamForWriting (const Stream &stream) {
                AddHandleForWriting (stream.handle);
            }

            /// \brief
            /// Blocking select.
            /// \return true = Call IsHandleReady* to check which
            /// handle caused select to exit.
            bool Select ();
            /// \brief
            /// Select with timeout.
            /// \param[in] timeSpec How long to wait for handles to become ready.
            /// \return true = Call IsHandleReady* to check which
            /// handle caused select to exit.
            bool Select (const util::TimeSpec &timeSpec);

            /// \brief
            /// Call this from a different thread to have the waiting
            /// thread exit the Select call.
            void Break ();

            /// \brief
            /// Return true if a given raw handle has data available in it's
            /// read buffers.
            /// \param[in] handle Handle to check for readiness.
            /// \return true = The handle is ready for reading.
            bool IsHandleReadyForReading (THEKOGANS_UTIL_HANDLE handle) const;
            /// \brief
            /// Return true if a given stream has data available in it's read buffers.
            /// \param[in] stream \see{Stream} to check for readiness.
            /// \return true = The stream is ready for reading.
            inline bool IsStreamReadyForReading (const Stream &stream) const {
                return IsHandleReadyForReading (stream.handle);
            }
            /// \brief
            /// Return true if a given raw handle is ready to receive more
            /// data in to it's write buffers.
            /// \param[in] handle Handle to check for readiness.
            /// \return true = The handle is ready for writing.
            bool IsHandleReadyForWriting (THEKOGANS_UTIL_HANDLE handle) const;
            /// \brief
            /// Return true if a given stream is ready to receive more
            /// data in to it's write buffers.
            /// \param[in] stream \see{Stream} to check for readiness.
            /// \return true = The stream is ready for writing.
            inline bool IsStreamReadyForWriting (const Stream &stream) const {
                return IsHandleReadyForWriting (stream.handle);
            }

            /// \brief
            /// StreamSelector is neither copy constructable, nor assignable.
            THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (StreamSelector)
        };

    } // namespace stream
} // namespace thekogans

#endif // !defined (__thekogans_stream_StreamSelector_h)
