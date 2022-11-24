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

#include "thekogans/util/Environment.h"

#if defined (TOOLCHAIN_OS_Windows)

#include <cassert>
#include "thekogans/util/Exception.h"
#include "thekogans/stream/AsyncIoEventSink.h"
#include "thekogans/stream/NamedPipe.h"

namespace thekogans {
    namespace stream {

        void NamedPipe::Write (
                const void *buffer,
                std::size_t count) {
            if (buffer != 0 && count > 0) {
                DWORD numberOfBytesWriten = 0;
                ReadWriteOverlapped::SharedPtr overlapped (
                    new ReadWriteOverlapped (*this, buffer, count));
                if (!WriteFile (
                        handle,
                        overlapped->buffer.GetReadPtr (),
                        (DWORD)overlapped->buffer.GetDataAvailableForReading (),
                        0,
                        overlapped.Get ())) {
                    THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_UTIL_OS_ERROR_CODE;
                    if (errorCode != ERROR_IO_PENDING) {
                        Produce (
                            std::bind (
                                &StreamEvents::OnStreamError,
                                std::placeholders::_1,
                                SharedPtr (this),
                                THEKOGANS_UTIL_ERROR_CODE_EXCEPTION (errorCode)));
                        return;
                    }
                }
                overlapped.Release ();
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        void NamedPipe::WriteBuffer (util::Buffer buffer) {
            if (!buffer.IsEmpty ()) {
                ReadWriteOverlapped::SharedPtr overlapped (
                    new ReadWriteOverlapped (*this, std::move (buffer)));
                if (!WriteFile (
                        handle,
                        overlapped->buffer.GetReadPtr (),
                        (ULONG)overlapped->buffer.GetDataAvailableForReading (),
                        0,
                        overlapped.Get ())) {
                    THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_UTIL_OS_ERROR_CODE;
                    if (errorCode != ERROR_IO_PENDING) {
                        Produce (
                            std::bind (
                                &StreamEvents::OnStreamError,
                                std::placeholders::_1,
                                SharedPtr (this),
                                THEKOGANS_UTIL_ERROR_CODE_EXCEPTION (errorCode)));
                        return;
                    }
                }
                overlapped.Release ();
            }
        }

        std::size_t NamedPipe::GetDataAvailable () {
            DWORD totalBytesAvailable = 0;
            if (!PeekNamedPipe (handle, 0, 0, 0, &totalBytesAvailable, 0)) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE);
            }
            return totalBytesAvailable;
        }

        void NamedPipe::InitAsyncIo () {
            PostAsyncRead ();
        }

        void NamedPipe::PostAsyncRead () {
            ReadWriteOverlapped::SharedPtr overlapped (
                new ReadWriteOverlapped (*this, GetBufferLength ()));
            if (!ReadFile (
                    handle,
                    overlapped->buffer.GetWritePtr (),
                    (DWORD)overlapped->buffer.GetDataAvailableForWriting (),
                    0,
                    overlapped.Get ())) {
                THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_UTIL_OS_ERROR_CODE;
                if (errorCode != ERROR_IO_PENDING) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (errorCode);
                }
            }
            overlapped.Release ();
        }

        void NamedPipe::HandleOverlapped (Overlapped &overlapped) throw () {
            if (overlapped.event == EventDisconnect) {
                Produce (
                    std::bind (
                        &StreamEvents::OnStreamDisconnect,
                        std::placeholders::_1,
                        SharedPtr (this)));
            }
            else if (overlapped.event == EventRead) {
                THEKOGANS_UTIL_TRY {
                    ReadWriteOverlapped &readWriteOverlapped = (ReadWriteOverlapped &)overlapped;
                    if (!readWriteOverlapped.buffer.IsEmpty ()) {
                        PostAsyncRead ();
                        HandleStreamDisconnect (*this);
                        Produce (
                            std::bind (
                                &StreamEvents::OnStreamRead,
                                std::placeholders::_1,
                                SharedPtr (this),
                                std::move (readWriteOverlapped.buffer)));
                    }
                    else {
                        Produce (
                            std::bind (
                                &StreamEvents::OnStreamDisconnect,
                                std::placeholders::_1,
                                SharedPtr (this)));
                    }
                }
                THEKOGANS_UTIL_CATCH (util::Exception) {
                    THEKOGANS_UTIL_EXCEPTION_NOTE_LOCATION (exception);
                    Produce (
                        std::bind (
                            &StreamEvents::OnStreamError,
                            std::placeholders::_1,
                            SharedPtr (this),
                            exception));
                }
            }
            else if (overlapped.event == EventWrite) {
                ReadWriteOverlapped &readWriteOverlapped = (ReadWriteOverlapped &)overlapped;
                assert (readWriteOverlapped.buffer.IsEmpty ());
                Produce (
                    std::bind (
                        &StreamEvents::OnStreamWrite,
                        std::placeholders::_1,
                        SharedPtr (this),
                        std::move (readWriteOverlapped.buffer)));
            }
        }

    } // namespace stream
} // namespace thekogans

#endif // defined (TOOLCHAIN_OS_Windows)
