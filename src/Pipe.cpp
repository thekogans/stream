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
    #if !defined (_WINDOWS_)
        #if !defined (WIN32_LEAN_AND_MEAN)
            #define WIN32_LEAN_AND_MEAN
        #endif // !defined (WIN32_LEAN_AND_MEAN)
        #if !defined (NOMINMAX)
            #define NOMINMAX
        #endif // !defined (NOMINMAX)
        #include <windows.h>
    #endif // !defined (_WINDOWS_)
#else // defined (TOOLCHAIN_OS_Windows)
    #include <sys/types.h>
    #include <sys/ioctl.h>
    #include <fcntl.h>
    #include <unistd.h>
#endif // defined (TOOLCHAIN_OS_Windows)
#include <cassert>
#if defined (TOOLCHAIN_OS_Windows)
    #include "thekogans/util/WindowsUtils.h"
#endif // defined (TOOLCHAIN_OS_Windows)
#include "thekogans/util/Exception.h"
#include "thekogans/util/LoggerMgr.h"
#include "thekogans/stream/AsyncIoEventQueue.h"
#include "thekogans/stream/AsyncIoEventSink.h"
#include "thekogans/stream/Pipe.h"

namespace thekogans {
    namespace stream {

        THEKOGANS_UTIL_IMPLEMENT_HEAP_WITH_LOCK (Pipe, util::SpinLock)

        void Pipe::Create (
                Pipe &readPipe,
                Pipe &writePipe) {
            THEKOGANS_UTIL_HANDLE handles[2] = {
                THEKOGANS_UTIL_INVALID_HANDLE_VALUE,
                THEKOGANS_UTIL_INVALID_HANDLE_VALUE
            };
            if (pipe (handles) < 0) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE);
            }
            readPipe.handle = handles[0];
            writePipe.handle = handles[1];
        }

        std::size_t Pipe::Read (
                void *buffer,
                std::size_t count) {
            if (buffer != 0 && count > 0) {
            #if defined (TOOLCHAIN_OS_Windows)
                DWORD countRead = 0;
                if (!ReadFile (handle, buffer, (DWORD)count, &countRead, 0)) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_UTIL_OS_ERROR_CODE);
                }
                return countRead;
            #else // defined (TOOLCHAIN_OS_Windows)
                ssize_t countRead = read (handle, buffer, count);
                if (countRead < 0) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_UTIL_OS_ERROR_CODE);
                }
                return (std::size_t)countRead;
            #endif // defined (TOOLCHAIN_OS_Windows)
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        std::size_t Pipe::Write (
                const void *buffer,
                std::size_t count) {
            if (buffer != 0 && count > 0) {
            #if defined (TOOLCHAIN_OS_Windows)
                DWORD countWritten = 0;
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
                            return 0;
                        }
                    }
                    overlapped.Release ();
                }
                else if (!WriteFile (handle, buffer, (DWORD)count, &countWritten, 0)) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_UTIL_OS_ERROR_CODE);
                }
                return countWritten;
            #else // defined (TOOLCHAIN_OS_Windows)
                ssize_t countWritten = 0;
                if (IsAsync ()) {
                    asyncInfo->EnqBufferBack (
                        AsyncInfo::BufferInfo::UniquePtr (
                            new AsyncInfo::WriteBufferInfo (*this, buffer, count)));
                }
                else {
                    countWritten = write (handle, buffer, count);
                    if (countWritten < 0) {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                            THEKOGANS_UTIL_OS_ERROR_CODE);
                    }
                }
                return (std::size_t)countWritten;
            #endif // defined (TOOLCHAIN_OS_Windows)
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        void Pipe::WriteBuffer (util::Buffer buffer) {
            if (!buffer.IsEmpty ()) {
                if (IsAsync ()) {
                #if defined (TOOLCHAIN_OS_Windows)
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
                #else // defined (TOOLCHAIN_OS_Windows)
                    asyncInfo->EnqBufferBack (
                        AsyncInfo::BufferInfo::UniquePtr (
                            new AsyncInfo::WriteBufferInfo (*this, std::move (buffer))));
                #endif // defined (TOOLCHAIN_OS_Windows)
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "%s", "WriteBuffer is called on a blocking pipe.");
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        std::size_t Pipe::GetDataAvailable () {
        #if defined (TOOLCHAIN_OS_Windows)
            DWORD totalBytesAvailable = 0;
            if (!PeekNamedPipe (handle, 0, 0, 0, &totalBytesAvailable, 0)) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE);
            }
            return totalBytesAvailable;
        #else // defined (TOOLCHAIN_OS_Windows)
            unsigned long value = 0;
            if (ioctl (handle, FIONREAD, &value) < 0) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE);
            }
            return value;
        #endif // defined (TOOLCHAIN_OS_Windows)
        }

        void Pipe::InitAsyncIo () {
        #if defined (TOOLCHAIN_OS_Windows)
            PostAsyncRead ();
        #else // defined (TOOLCHAIN_OS_Windows)
            SetBlocking (false);
            asyncInfo->AddStreamForEvents (AsyncInfo::EventRead);
        #endif // defined (TOOLCHAIN_OS_Windows)
        }

    #if defined (TOOLCHAIN_OS_Windows)
        void Pipe::PostAsyncRead () {
            if (asyncInfo->bufferLength != 0) {
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

        void Pipe::HandleOverlapped (AsyncInfo::Overlapped &overlapped) throw () {
            if (overlapped.event == AsyncInfo::EventRead) {
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
    #else // defined (TOOLCHAIN_OS_Windows)
        void Pipe::SetBlocking (bool blocking) {
            int flags = fcntl (handle, F_GETFL, 0);
            if (blocking) {
                flags &= ~O_NONBLOCK;
            }
            else {
                flags |= O_NONBLOCK;
            }
            if (fcntl (handle, F_SETFL, flags) < 0) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE);
            }
        }

        void Pipe::HandleAsyncEvent (util::ui32 event) throw () {
            if (event == AsyncInfo::EventDisconnect) {
                asyncInfo->eventSink.HandleStreamDisconnect (*this);
            }
            else if (event == AsyncInfo::EventRead) {
                THEKOGANS_UTIL_TRY {
                    std::size_t bufferLength = GetDataAvailable ();
                    if (bufferLength != 0) {
                        util::Buffer buffer =
                            asyncInfo->eventSink.GetBuffer (
                                *this, util::NetworkEndian, bufferLength);
                        if (buffer.AdvanceWriteOffset (
                                Read (
                                    buffer.GetWritePtr (),
                                    bufferLength)) > 0) {
                            asyncInfo->eventSink.HandleStreamRead (
                                *this, std::move (buffer));
                        }
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
            else if (event == AsyncInfo::EventWrite) {
                asyncInfo->WriteBuffers ();
            }
        }
    #endif // defined (TOOLCHAIN_OS_Windows)

    } // namespace stream
} // namespace thekogans
