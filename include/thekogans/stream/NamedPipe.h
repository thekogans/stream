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

        struct _LIB_THEKOGANS_STREAM_DECL NamedPipe : public Stream {
            /// \brief
            /// NamedPipe is a \see{Stream}.
            THEKOGANS_STREAM_DECLARE_STREAM (NamedPipe)

            /// \brief
            /// ctor.
            /// Wrap an OS handle.
            /// \param[in] handle OS stream handle to wrap.
            explicit NamedPipe (THEKOGANS_UTIL_HANDLE handle) :
                Stream (handle) {}

            // Stream
            /// \brief
            /// Read bytes from the stream.
            /// \param[in] bufferLength Buffer length for async WSARecv[From | Msg].
            virtual void Read (std::size_t bufferLength = DEFAULT_BUFFER_LENGTH) override;
            /// \brief
            /// Write buffer the stream.
            /// \param[in] buffer Buffer to write.
            virtual void Write (util::Buffer buffer) override;

            void SetMode (DWORD pipeMode);

        protected:
            // Stream
            /// \brief
            /// Return number of bytes available for reading.
            /// \return Number of bytes available for reading.
            virtual std::size_t GetDataAvailableForReading () const override;
            virtual std::size_t ReadHelper (
                void *buffer,
                std::size_t bufferLength) override;
            virtual std::size_t WriteHelper (
                const void *buffer,
                std::size_t bufferLength) override;
        };

    } // namespace stream
} // namespace thekogans

#endif // defined (TOOLCHAIN_OS_Windows)

#endif // !defined (__thekogans_stream_NamedPipe_h)
