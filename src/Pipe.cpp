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
#include "thekogans/stream/Pipe.h"

namespace thekogans {
    namespace stream {

        THEKOGANS_STREAM_IMPLEMENT_STREAM (Pipe)

        Pipe::Pipe (THEKOGANS_UTIL_HANDLE handle) :
                Stream (handle) {
        #if !defined (TOOLCHAIN_OS_Windows)
            SetBlocking (false);
        #endif // !defined (TOOLCHAIN_OS_Windows)
        }

        void Pipe::Create (
                Pipe::SharedPtr &readPipe,
                Pipe::SharedPtr &writePipe) {
            THEKOGANS_UTIL_HANDLE handles[2] = {
                THEKOGANS_UTIL_INVALID_HANDLE_VALUE,
                THEKOGANS_UTIL_INVALID_HANDLE_VALUE
            };
            if (pipe (handles) < 0) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE);
            }
            readPipe.Reset (new Pipe (handles[0]));
            writePipe.Reset (new Pipe (handles[1]));
        }

        void Pipe::Read (std::size_t bufferLength) {
            THEKOGANS_UTIL_TRY {
            #if defined (TOOLCHAIN_OS_Windows)
                std::unique_ptr<ReadOverlapped> overlapped (new ReadOverlapped (bufferLength));
                if (!ReadFile (
                        handle,
                        overlapped->buffer.GetWritePtr (),
                        (DWORD)overlapped->buffer.GetDataAvailableForWriting (),
                        0,
                        overlapped.get ())) {
                    THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_UTIL_OS_ERROR_CODE;
                    if (errorCode != ERROR_IO_PENDING) {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (errorCode);
                    }
                }
                overlapped.release ();
            #else // defined (TOOLCHAIN_OS_Windows)
                EnqOverlapped (
                    std::unique_ptr<Overlapped> (new ReadOverlapped (bufferLength)),
                    in);
            #endif // defined (TOOLCHAIN_OS_Windows)
            }
            THEKOGANS_UTIL_CATCH (util::Exception) {
                THEKOGANS_UTIL_EXCEPTION_NOTE_LOCATION (exception);
                HandleError (exception);
            }
        }

        void Pipe::Write (util::Buffer buffer) {
            if (!buffer.IsEmpty ()) {
                THEKOGANS_UTIL_TRY {
                #if defined (TOOLCHAIN_OS_Windows)
                    std::unique_ptr<WriteOverlapped> overlapped (new WriteOverlapped (std::move (buffer)));
                    if (!WriteFile (
                            handle,
                            overlapped->buffer.GetReadPtr (),
                            (ULONG)overlapped->buffer.GetDataAvailableForReading (),
                            0,
                            overlapped.get ())) {
                        THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_UTIL_OS_ERROR_CODE;
                        if (errorCode != ERROR_IO_PENDING) {
                            THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (errorCode);
                        }
                    }
                    overlapped.release ();
                #else // defined (TOOLCHAIN_OS_Windows)
                    EnqOverlapped (
                        std::unique_ptr<Overlapped> (new WriteOverlapped (std::move (buffer))),
                        out);
                #endif // defined (TOOLCHAIN_OS_Windows)
                }
                THEKOGANS_UTIL_CATCH (util::Exception) {
                    THEKOGANS_UTIL_EXCEPTION_NOTE_LOCATION (exception);
                    HandleError (exception);
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

    #if !defined (TOOLCHAIN_OS_Windows)
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
    #endif // !defined (TOOLCHAIN_OS_Windows)

        std::size_t Pipe::GetDataAvailableForReading () const {
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

        std::size_t Pipe::ReadHelper (
                void *buffer,
                std::size_t bufferLength) {
            if (buffer != 0 && bufferLength > 0) {
            #if defined (TOOLCHAIN_OS_Windows)
                DWORD countRead = 0;
                if (!ReadFile (handle, buffer, (DWORD)bufferLength, &countRead, 0)) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_UTIL_OS_ERROR_CODE);
                }
                return countRead;
            #else // defined (TOOLCHAIN_OS_Windows)
                ssize_t countRead = read (handle, buffer, bufferLength);
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

        std::size_t Pipe::WriteHelper (
                const void *buffer,
                std::size_t bufferLength) {
            if (buffer != 0 && bufferLength > 0) {
            #if defined (TOOLCHAIN_OS_Windows)
                DWORD countWritten = 0;
                if (!WriteFile (handle, buffer, (DWORD)bufferLength, &countWritten, 0)) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_UTIL_OS_ERROR_CODE);
                }
                return countWritten;
            #else // defined (TOOLCHAIN_OS_Windows)
                ssize_t countWritten = write (handle, buffer, bufferLength);
                if (countWritten < 0) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_UTIL_OS_ERROR_CODE);
                }
                return (std::size_t)countWritten;
            #endif // defined (TOOLCHAIN_OS_Windows)
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

    } // namespace stream
} // namespace thekogans
