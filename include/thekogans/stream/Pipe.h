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
        /// \struct Pipe Pipe.h thekogans/stream/Pipe.h
        ///
        /// \brief
        /// Pipe wraps up an unnamed pipe. On Windows the pipes are
        /// actually created from named pipes so that we can take
        /// advantage of overlapped (async) io.

        struct _LIB_THEKOGANS_STREAM_DECL Pipe : public Stream {
            /// \brief
            /// Pipe is a \see{Stream}.
            THEKOGANS_STREAM_DECLARE_STREAM (Pipe)

            /// \brief
            /// ctor. \see{Stream}
            /// Used as input to Pipe::Create.
            /// \param[in] handle OS stream handle to wrap.
            explicit Pipe (THEKOGANS_UTIL_HANDLE handle);

            /// \brief
            /// Create both ends of the pipe.
            /// \param[out] readPipe The reading end of the pipe.
            /// \param[out] writePipe The writing end of the pipe.
            static void Create (
                Pipe::SharedPtr &readPipe,
                Pipe::SharedPtr &writePipe);

            // Stream
            /// \brief
            /// Return number of bytes available for reading.
            /// \return Number of bytes available for reading.
            virtual std::size_t GetDataAvailableForReading () const override;
            /// \brief
            /// Async read bytes from the stream.
            virtual void Read (std::size_t bufferLength = DEFAULT_BUFFER_LENGTH) override;
            /// \brief
            /// Async write a buffer to the stream.
            /// \param[in] buffer Buffer to write.
            virtual void Write (util::Buffer buffer) override;

        protected:
        #if !defined (TOOLCHAIN_OS_Windows)
            /// \brief
            /// Put the pipe in (non-)blocking mode.
            /// \param[in] blocking true = blocking, false = non-blocking
            void SetBlocking (bool blocking);
        #endif // !defined (TOOLCHAIN_OS_Windows)

            // Stream
            /// \brief
            /// ReadHelper needs to be implemented by every concrete class to provide
            /// blocking reads. It's called by the framework to perform data extraction
            /// from os to application buffers after we've been informed of it's arrival.
            /// NOTE: The framework exopects this function to throw on error.
            /// \param[out] buffer Where to read the data.
            /// \param[in] bufferLength Size of buffer.
            /// \return Count of bytes actually read.
            virtual std::size_t ReadHelper (
                void *buffer,
                std::size_t bufferLength) override;
            virtual std::size_t WriteHelper (
                const void *buffer,
                std::size_t bufferLength) override;
        };

    } // namespace stream
} // namespace thekogans

#endif // !defined (__thekogans_stream_Pipe_h)
