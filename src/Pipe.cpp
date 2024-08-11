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
    #include "thekogans/util/os/windows/WindowsHeader.h"
#else // defined (TOOLCHAIN_OS_Windows)
    #include <sys/types.h>
    #include <sys/ioctl.h>
    #include <fcntl.h>
    #include <unistd.h>
#endif // defined (TOOLCHAIN_OS_Windows)
#include <cassert>
#if defined (TOOLCHAIN_OS_Windows)
    #include "thekogans/util/os/windows/WindowsUtils.h"
#endif // defined (TOOLCHAIN_OS_Windows)
#include "thekogans/util/Exception.h"
#include "thekogans/util/LoggerMgr.h"
#include "thekogans/stream/Overlapped.h"
#include "thekogans/stream/Pipe.h"

namespace thekogans {
    namespace stream {

        THEKOGANS_STREAM_IMPLEMENT_STREAM (Pipe)

        Pipe::Pipe (THEKOGANS_UTIL_HANDLE handle) :
                Stream (handle) {
        #if !defined (TOOLCHAIN_OS_Windows)
            int flags = fcntl (handle, F_GETFL, 0);
            flags |= O_NONBLOCK;
            if (fcntl (handle, F_SETFL, flags) < 0) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE);
            }
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

        namespace {
            struct ReadOverlapped : public Overlapped {
                THEKOGANS_STREAM_DECLARE_OVERLAPPED (ReadOverlapped)

                util::Buffer::SharedPtr buffer;

                ReadOverlapped (std::size_t bufferLength) :
                    buffer (new util::Buffer (util::NetworkEndian, bufferLength)) {}

                virtual ssize_t Prolog (Stream::SharedPtr stream) throw () override {
                #if defined (TOOLCHAIN_OS_Windows)
                    return GetError () == ERROR_SUCCESS ?
                        buffer->AdvanceWriteOffset (GetCount ()) : -1;
                #else // defined (TOOLCHAIN_OS_Windows)
                    ssize_t countRead = read (
                        stream->GetHandle (),
                        buffer->GetWritePtr (),
                        buffer->GetDataAvailableForWriting ());
                    if (countRead < 0) {
                        SetError (THEKOGANS_UTIL_OS_ERROR_CODE);
                        SetCount (0);
                        return -1;
                    }
                    SetError (0);
                    SetCount (countRead);
                    return buffer->AdvanceWriteOffset ((std::size_t)countRead);
                #endif // defined (TOOLCHAIN_OS_Windows)
                }

                virtual bool Epilog (Stream::SharedPtr stream) throw () override {
                    stream->util::Producer<StreamEvents>::Produce (
                        std::bind (
                            &StreamEvents::OnStreamRead,
                            std::placeholders::_1,
                            stream,
                            buffer));
                    if (stream->IsChainRead ()) {
                        stream->Read (buffer->GetLength ());
                    }
                    return true;
                }
            };

            THEKOGANS_STREAM_IMPLEMENT_OVERLAPPED (ReadOverlapped)
        }

        void Pipe::Read (std::size_t bufferLength) {
            if (bufferLength > 0) {
            #if defined (TOOLCHAIN_OS_Windows)
                ReadOverlapped::SharedPtr overlapped (new ReadOverlapped (bufferLength));
                if (!ReadFile (
                        handle,
                        overlapped->buffer->GetWritePtr (),
                        (DWORD)overlapped->buffer->GetDataAvailableForWriting (),
                        0,
                        overlapped.Get ())) {
                    THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_UTIL_OS_ERROR_CODE;
                    if (errorCode != ERROR_IO_PENDING) {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (errorCode);
                    }
                }
                overlapped.Release ();
            #else // defined (TOOLCHAIN_OS_Windows)
                EnqOverlapped (new ReadOverlapped (bufferLength), in);
            #endif // defined (TOOLCHAIN_OS_Windows)
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        namespace {
            struct WriteOverlapped : public Overlapped {
                THEKOGANS_STREAM_DECLARE_OVERLAPPED (WriteOverlapped)

                util::Buffer::SharedPtr buffer;

                WriteOverlapped (util::Buffer::SharedPtr buffer_) :
                    buffer (buffer_) {}

                virtual ssize_t Prolog (Stream::SharedPtr stream) throw () override {
                #if defined (TOOLCHAIN_OS_Windows)
                    return GetError () == ERROR_SUCCESS ?
                        buffer->AdvanceReadOffset (GetCount ()) : -1;
                #else // defined (TOOLCHAIN_OS_Windows)
                    ssize_t countWritten = write (
                        stream->GetHandle (),
                        buffer->GetReadPtr (),
                        buffer->GetDataAvailableForReading ());
                    if (countWritten < 0) {
                        SetError (THEKOGANS_UTIL_OS_ERROR_CODE);
                        SetCount (0);
                        return -1;
                    }
                    SetError (0);
                    SetCount (countWritten);
                    return buffer->AdvanceReadOffset ((std::size_t)countWritten);
                #endif // defined (TOOLCHAIN_OS_Windows)
                }

                virtual bool Epilog (Stream::SharedPtr stream) throw () override {
                #if !defined (TOOLCHAIN_OS_Windows)
                    if (buffer->IsEmpty ()) {
                #endif // !defined (TOOLCHAIN_OS_Windows)
                        stream->util::Producer<StreamEvents>::Produce (
                            std::bind (
                                &StreamEvents::OnStreamWrite,
                                std::placeholders::_1,
                                stream,
                                buffer));
                #if defined (TOOLCHAIN_OS_Windows)
                        return true;
                #else // defined (TOOLCHAIN_OS_Windows)
                    }
                    return buffer->IsEmpty ();
                #endif // defined (TOOLCHAIN_OS_Windows)
                }
            };

            THEKOGANS_STREAM_IMPLEMENT_OVERLAPPED (WriteOverlapped)
        }

        void Pipe::Write (util::Buffer::SharedPtr buffer) {
            if (!buffer->IsEmpty ()) {
            #if defined (TOOLCHAIN_OS_Windows)
                WriteOverlapped::SharedPtr overlapped (new WriteOverlapped (buffer));
                if (!WriteFile (
                        handle,
                        overlapped->buffer->GetReadPtr (),
                        (ULONG)overlapped->buffer->GetDataAvailableForReading (),
                        0,
                        overlapped.Get ())) {
                    THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_UTIL_OS_ERROR_CODE;
                    if (errorCode != ERROR_IO_PENDING) {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (errorCode);
                    }
                }
                overlapped.Release ();
            #else // defined (TOOLCHAIN_OS_Windows)
                EnqOverlapped (new WriteOverlapped (buffer), out);
            #endif // defined (TOOLCHAIN_OS_Windows)
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

    } // namespace stream
} // namespace thekogans
