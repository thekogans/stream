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
#include "thekogans/stream/Stream.h"

namespace thekogans {
    namespace stream {

        /// \struct NamedPipe NamedPipe.h thekogans/stream/NamedPipe.h
        ///
        /// \brief
        /// NamedPipe is the base class for both ClientNamedPipe
        /// and ServerNamedPipe. While not an abstract base, there
        /// is very little reason to create instances of this class.
        /// All it does is abstract out the read and write apis.

        struct _LIB_THEKOGANS_STREAM_DECL NamedPipe : public Stream {
            /// \enum
            /// Named pipe types.
            enum PipeType {
                /// \brief
                /// Create a stream named pipe.
                Byte,
                /// \brief
                /// Create a datagram named pipe.
                Message
            };

            /// \brief
            /// Read timeout (util::TimeSpec::Zero == no timeout).
            util::TimeSpec readTimeout;
            /// \brief
            /// Write timeout (util::TimeSpec::Zero == no timeout).
            util::TimeSpec writeTimeout;

            /// \brief
            /// ctor.
            /// Wrap an OS handle.
            /// \param[in] handle OS stream handle to wrap.
            NamedPipe (THEKOGANS_UTIL_HANDLE handle = THEKOGANS_UTIL_INVALID_HANDLE_VALUE) :
                Stream (handle),
                readTimeout (util::TimeSpec::Zero),
                writeTimeout (util::TimeSpec::Zero) {}

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
            /// stream is already async, and Stream::AsyncInfo has
            /// been created. At this point the stream should do
            /// whatever stream specific initialization it needs to
            /// do.
            virtual void InitAsyncIo ();
            /// \brief
            /// Initiate an overlapped ReadFile.
            void PostAsyncRead ();
            /// \brief
            /// Used by AsyncIoEventQueue to notify the stream that
            /// an overlapped operation has completed successfully.
            /// \param[in] overlapped Overlapped that completed successfully.
            virtual void HandleOverlapped (AsyncInfo::Overlapped &overlapped) throw ();

            /// \brief
            /// Streams are neither copy constructable, nor assignable.
            THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (NamedPipe)
        };

    } // namespace stream
} // namespace thekogans

#endif // defined (TOOLCHAIN_OS_Windows)

#endif // !defined (__thekogans_stream_NamedPipe_h)
