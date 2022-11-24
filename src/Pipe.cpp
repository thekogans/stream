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

        void Pipe::Write (
                const void *buffer,
                std::size_t count) {
            if (buffer != 0 && count > 0) {
            #if defined (TOOLCHAIN_OS_Windows)
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
                        eventSink.HandleStreamError (
                            *this,
                            THEKOGANS_UTIL_ERROR_CODE_EXCEPTION (errorCode));
                        return 0;
                    }
                }
                overlapped.Release ();
            #else // defined (TOOLCHAIN_OS_Windows)
                EnqBufferBack (
                    BufferInfo::UniquePtr (
                        new WriteBufferInfo (*this, buffer, count)));
            #endif // defined (TOOLCHAIN_OS_Windows)
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        void Pipe::WriteBuffer (util::Buffer buffer) {
            if (!buffer.IsEmpty ()) {
            #if defined (TOOLCHAIN_OS_Windows)
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
                        eventSink.HandleStreamError (
                            *this,
                            THEKOGANS_UTIL_ERROR_CODE_EXCEPTION (errorCode));
                        return;
                    }
                }
                overlapped.Release ();
            #else // defined (TOOLCHAIN_OS_Windows)
                EnqBufferBack (
                    BufferInfo::UniquePtr (
                        new WriteBufferInfo (*this, std::move (buffer))));
            #endif // defined (TOOLCHAIN_OS_Windows)
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
            AddStreamForEvents (EventRead);
        #endif // defined (TOOLCHAIN_OS_Windows)
        }

    #if defined (TOOLCHAIN_OS_Windows)
        void Pipe::PostAsyncRead () {
            if (bufferLength != 0) {
                ReadWriteOverlapped::SharedPtr overlapped (
                    new ReadWriteOverlapped (*this, bufferLength));
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

        void Pipe::HandleOverlapped (Overlapped &overlapped) throw () {
            if (overlapped.event == EventRead) {
                THEKOGANS_UTIL_TRY {
                    ReadWriteOverlapped &readWriteOverlapped =
                        (ReadWriteOverlapped &)overlapped;
                    if (!readWriteOverlapped.buffer.IsEmpty ()) {
                        PostAsyncRead ();
                        eventSink.HandleStreamRead (
                            *this, std::move (readWriteOverlapped.buffer));
                    }
                    else {
                        eventSink.HandleStreamDisconnect (*this);
                    }
                }
                THEKOGANS_UTIL_CATCH (util::Exception) {
                    THEKOGANS_UTIL_EXCEPTION_NOTE_LOCATION (exception);
                    eventSink.HandleStreamError (*this, exception);
                }
            }
            else if (overlapped.event == EventWrite) {
                ReadWriteOverlapped &readWriteOverlapped =
                    (ReadWriteOverlapped &)overlapped;
                assert (readWriteOverlapped.buffer.IsEmpty ());
                eventSink.HandleStreamWrite (
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
            if (event == EventDisconnect) {
                eventSink.HandleStreamDisconnect (*this);
            }
            else if (event == EventRead) {
                THEKOGANS_UTIL_TRY {
                    std::size_t bufferLength = GetDataAvailable ();
                    if (bufferLength != 0) {
                        util::Buffer buffer =
                            eventSink.GetBuffer (
                                *this, util::NetworkEndian, bufferLength);
                        if (buffer.AdvanceWriteOffset (
                                Read (
                                    buffer.GetWritePtr (),
                                    bufferLength)) > 0) {
                            eventSink.HandleStreamRead (
                                *this, std::move (buffer));
                        }
                    }
                    else {
                        eventSink.HandleStreamDisconnect (*this);
                    }
                }
                THEKOGANS_UTIL_CATCH (util::Exception) {
                    THEKOGANS_UTIL_EXCEPTION_NOTE_LOCATION (exception);
                    eventSink.HandleStreamError (*this, exception);
                }
            }
            else if (event == EventWrite) {
                WriteBuffers ();
            }
        }
    #endif // defined (TOOLCHAIN_OS_Windows)

    } // namespace stream
} // namespace thekogans
