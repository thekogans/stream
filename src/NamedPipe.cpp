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

#if defined (TOOLCHAIN_OS_Windows)

#include <cassert>
#include "thekogans/util/Exception.h"
#include "thekogans/stream/AsyncIoEventSink.h"
#include "thekogans/stream/NamedPipe.h"

namespace thekogans {
    namespace stream {

        std::size_t NamedPipe::Read (
                void *buffer,
                std::size_t count) {
            if (buffer != 0 && count > 0) {
                DWORD numberOfBytesRead = 0;
                TimedOverlapped::SharedPtr overlapped;
                if (readTimeout != util::TimeSpec::Zero) {
                    overlapped.Reset (new TimedOverlapped);
                }
                if (!ReadFile (
                        handle,
                        buffer,
                        (DWORD)count,
                        overlapped.Get () != 0 ? 0 : &numberOfBytesRead,
                        overlapped.Get ())) {
                    THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_UTIL_OS_ERROR_CODE;
                    if (errorCode == ERROR_IO_PENDING) {
                        numberOfBytesRead = overlapped->Wait (handle, readTimeout);
                    }
                    else {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (errorCode);
                    }
                }
                else if (overlapped.Get () != 0 &&
                       !GetOverlappedResult (
                           handle,
                           overlapped.Get (),
                           &numberOfBytesRead,
                           FALSE)) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_UTIL_OS_ERROR_CODE);
                }
                return numberOfBytesRead;
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        std::size_t NamedPipe::Write (
                const void *buffer,
                std::size_t count) {
            if (buffer != 0 && count > 0) {
                DWORD numberOfBytesWriten = 0;
                if (IsAsync ()) {
                    AsyncInfo::ReadWriteOverlapped::SharedPtr overlapped (
                        new AsyncInfo::ReadWriteOverlapped (*this, buffer, count));
                    if (!WriteFile (
                            handle,
                            overlapped->buffer.GetReadPtr (),
                            (DWORD)overlapped->buffer.GetDataAvailableForReading (),
                            0,
                            overlapped.Get ())) {
                        THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_UTIL_OS_ERROR_CODE;
                        if (errorCode != ERROR_IO_PENDING) {
                            asyncInfo->eventSink.HandleStreamError (
                                *this,
                                THEKOGANS_UTIL_ERROR_CODE_EXCEPTION (errorCode));
                            return;
                        }
                    }
                    overlapped.Release ();
                }
                else {
                    TimedOverlapped::SharedPtr overlapped;
                    if (writeTimeout != util::TimeSpec::Zero) {
                        overlapped.Reset (new TimedOverlapped);
                    }
                    if (!WriteFile (
                            handle,
                            buffer,
                            (DWORD)count,
                            overlapped.Get () != 0 ? 0 : &numberOfBytesWriten,
                            overlapped.Get ())) {
                        THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_UTIL_OS_ERROR_CODE;
                        if (errorCode == ERROR_IO_PENDING) {
                            numberOfBytesWriten = overlapped->Wait (handle, writeTimeout);
                        }
                        else {
                            THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (errorCode);
                        }
                    }
                    else if (overlapped.Get () != 0 &&
                            !GetOverlappedResult (
                                handle,
                                overlapped.Get (),
                                &numberOfBytesWriten,
                                FALSE)) {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                            THEKOGANS_UTIL_OS_ERROR_CODE);
                    }
                }
                return numberOfBytesWriten;
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        void NamedPipe::WriteBuffer (util::Buffer buffer) {
            if (!buffer.IsEmpty ()) {
                if (IsAsync ()) {
                    AsyncInfo::ReadWriteOverlapped::SharedPtr overlapped (
                        new AsyncInfo::ReadWriteOverlapped (*this, std::move (buffer)));
                    if (!WriteFile (
                            handle,
                            overlapped->buffer.GetReadPtr (),
                            (ULONG)overlapped->buffer.GetDataAvailableForReading (),
                            0,
                            overlapped.Get ())) {
                        THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_UTIL_OS_ERROR_CODE;
                        if (errorCode != ERROR_IO_PENDING) {
                            asyncInfo->eventSink.HandleStreamError (
                                *this,
                                THEKOGANS_UTIL_ERROR_CODE_EXCEPTION (errorCode));
                            return;
                        }
                    }
                    overlapped.Release ();
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "%s", "WriteBuffer is called on a blocking named pipe.");
                }
            }
        }

        void NamedPipe::SetReadTimeout (const util::TimeSpec &timeSpec) {
            if (timeSpec != util::TimeSpec::Infinite) {
                readTimeout = timeSpec;
                if (IsAsync ()) {
                    THEKOGANS_UTIL_TRY {
                        asyncInfo->UpdateTimedStream (AsyncInfo::EventRead);
                    }
                    THEKOGANS_UTIL_CATCH (util::Exception) {
                        THEKOGANS_UTIL_EXCEPTION_NOTE_LOCATION (exception);
                        asyncInfo->eventSink.HandleStreamError (*this, exception);
                    }
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        void NamedPipe::SetWriteTimeout (const util::TimeSpec &timeSpec) {
            if (timeSpec != util::TimeSpec::Infinite) {
                writeTimeout = timeSpec;
                if (IsAsync ()) {
                    THEKOGANS_UTIL_TRY {
                        asyncInfo->UpdateTimedStream (AsyncInfo::EventWrite);
                    }
                    THEKOGANS_UTIL_CATCH (util::Exception) {
                        THEKOGANS_UTIL_EXCEPTION_NOTE_LOCATION (exception);
                        asyncInfo->eventSink.HandleStreamError (*this, exception);
                    }
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
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
            if (asyncInfo->bufferLength) {
                AsyncInfo::ReadWriteOverlapped::SharedPtr overlapped (
                    new AsyncInfo::ReadWriteOverlapped (*this, asyncInfo->bufferLength));
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
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        void NamedPipe::HandleOverlapped (AsyncInfo::Overlapped &overlapped) throw () {
            if (overlapped.event == AsyncInfo::EventDisconnect) {
                asyncInfo->eventSink.HandleStreamDisconnect (*this);
            }
            else if (overlapped.event == AsyncInfo::EventRead) {
                THEKOGANS_UTIL_TRY {
                    AsyncInfo::ReadWriteOverlapped &readWriteOverlapped =
                        (AsyncInfo::ReadWriteOverlapped &)overlapped;
                    if (!readWriteOverlapped.buffer.IsEmpty ()) {
                        PostAsyncRead ();
                        asyncInfo->eventSink.HandleStreamRead (
                            *this, std::move (readWriteOverlapped.buffer));
                    }
                    else {
                        asyncInfo->eventSink.HandleStreamDisconnect (*this);
                    }
                }
                THEKOGANS_UTIL_CATCH (util::Exception) {
                    THEKOGANS_UTIL_EXCEPTION_NOTE_LOCATION (exception);
                    asyncInfo->eventSink.HandleStreamError (*this, exception);
                }
            }
            else if (overlapped.event == AsyncInfo::EventWrite) {
                AsyncInfo::ReadWriteOverlapped &readWriteOverlapped =
                    (AsyncInfo::ReadWriteOverlapped &)overlapped;
                assert (readWriteOverlapped.buffer.IsEmpty ());
                asyncInfo->eventSink.HandleStreamWrite (
                    *this, std::move (readWriteOverlapped.buffer));
            }
        }

    } // namespace stream
} // namespace thekogans

#endif // defined (TOOLCHAIN_OS_Windows)
