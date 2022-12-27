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
#if defined (TOOLCHAIN_OS_Linux)
    #include <sys/epoll.h>
#elif defined (TOOLCHAIN_OS_OSX)
    #include <sys/types.h>
    #include <sys/event.h>
    #include <sys/time.h>
#endif // defined (TOOLCHAIN_OS_Linux)
#include <cstdio>
#include <cstdarg>
#include <cassert>
#include "thekogans/util/LockGuard.h"
#include "thekogans/util/Exception.h"
#include "thekogans/util/LoggerMgr.h"
#include "thekogans/stream/AsyncIoEventQueue.h"
#include "thekogans/stream/Stream.h"

namespace thekogans {
    namespace stream {

        THEKOGANS_STREAM_IMPLEMENT_STREAM_OVERLAPPED (Stream::ReadOverlapped)

        ssize_t Stream::ReadOverlapped::Prolog (Stream::SharedPtr stream) throw () {
        #if defined (TOOLCHAIN_OS_Windows)
            if (GetError () != ERROR_SUCCESS) {
                return -1;
            }
            buffer.AdvanceWriteOffset (GetCount ());
        #endif // defined (TOOLCHAIN_OS_Windows)
            if (buffer.IsEmpty ()) {
                THEKOGANS_UTIL_TRY {
                    buffer.Resize (stream->GetDataAvailable ());
                    buffer.AdvanceWriteOffset (
                        stream->ReadHelper (
                            buffer.GetWritePtr (),
                            buffer.GetDataAvailableForWriting ()));
                }
                THEKOGANS_UTIL_CATCH (util::Exception) {
                    SetError (exception.GetErrorCode ());
                    return -1;
                }
            }
            return buffer.GetDataAvailableForReading ();
        }

        THEKOGANS_STREAM_IMPLEMENT_STREAM_OVERLAPPED (Stream::WriteOverlapped)

        ssize_t Stream::WriteOverlapped::Prolog (Stream::SharedPtr stream) throw () {
        #if defined (TOOLCHAIN_OS_Windows)
            return GetError () == ERROR_SUCCESS ? buffer.AdvanceReadOffset (GetCount ()) : -1;
        #else // defined (TOOLCHAIN_OS_Windows)
            THEKOGANS_UTIL_TRY {
                return buffer.AdvanceReadOffset (
                    stream->WriteHelper (
                        buffer.GetReadPtr (),
                        buffer.GetDataAvailableForReading ()));
            }
            THEKOGANS_UTIL_CATCH (util::Exception) {
                SetError (exception.GetErrorCode ());
                return -1;
            }
        #endif // defined (TOOLCHAIN_OS_Windows)
        }

        Stream::Stream (THEKOGANS_UTIL_HANDLE handle_) :
                handle (handle_),
                token (this) {
            if (IsOpen ()) {
            #if defined (TOOLCHAIN_OS_Windows)
                if (CreateIoCompletionPort (
                        handle, AsyncIoEventQueue::Instance ().GetHandle (), (ULONG_PTR)token, 0) == 0) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_UTIL_OS_ERROR_CODE);
                }
            #endif // defined (TOOLCHAIN_OS_Windows)
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        Stream::~Stream () {
            THEKOGANS_UTIL_TRY {
                if (IsOpen ()) {
                #if defined (TOOLCHAIN_OS_Windows)
                    if (!::CloseHandle (handle)) {
                #else // defined (TOOLCHAIN_OS_Windows)
                    if (close (handle) < 0) {
                #endif // defined (TOOLCHAIN_OS_Windows)
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                            THEKOGANS_UTIL_OS_ERROR_CODE);
                    }
                }
            }
            THEKOGANS_UTIL_CATCH_AND_LOG_SUBSYSTEM (THEKOGANS_STREAM)
        }

        void Stream::Write (
                const void *buffer,
                std::size_t count) {
            if (buffer != 0 && count > 0) {
                util::Buffer buffer_ (
                    util::NetworkEndian,
                    (const util::ui8 *)buffer,
                    (const util::ui8 *)buffer + count);
                Write (std::move (buffer_));
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        void Stream::HandleError (const util::Exception &exception) throw () {
            Produce (
                std::bind (
                    &StreamEvents::OnStreamError,
                    std::placeholders::_1,
                    SharedPtr (this),
                    exception));
        }

        void Stream::HandleDisconnect () throw () {
            Produce (
                std::bind (
                    &StreamEvents::OnStreamDisconnect,
                    std::placeholders::_1,
                    SharedPtr (this)));
        }

    #if !defined (TOOLCHAIN_OS_Windows)
        void Stream::EnqOverlapped (
                std::unique_ptr<Overlapped> overlapped,
                std::list<std::unique_ptr<Overlapped>> &list,
                bool front) {
            THEKOGANS_UTIL_TRY {
                util::LockGuard<util::SpinLock> guard (spinLock);
                bool setMask = list.empty ();
                if (front) {
                    list.push_front (std::move (overlapped));
                }
                else {
                    list.push_back (std::move (overlapped));
                }
                if (setMask) {
                    AsyncIoEventQueue::Instance ().SetStreamEventMask (*this);
                }
            }
            THEKOGANS_UTIL_CATCH (util::Exception) {
                THEKOGANS_UTIL_EXCEPTION_NOTE_LOCATION (exception);
                HandleError (exception);
            }
        }

        std::unique_ptr<Stream::Overlapped> Stream::DeqOverlapped (std::list<std::unique_ptr<Overlapped>> &list) {
            THEKOGANS_UTIL_TRY {
                util::LockGuard<util::SpinLock> guard (spinLock);
                std::unique_ptr<Overlapped> overlapped;
                if (!list.empty ()) {
                    overlapped = std::move (list.front ());
                    list.pop_front ();
                    if (list.empty ()) {
                        AsyncIoEventQueue::Instance ().SetStreamEventMask (*this);
                    }
                }
                return overlapped;
            }
            THEKOGANS_UTIL_CATCH (util::Exception) {
                THEKOGANS_UTIL_EXCEPTION_NOTE_LOCATION (exception);
                HandleError (exception);
            }
        }

        std::unique_ptr<Stream::Overlapped> Stream::PumpAsyncIo (std::list<std::unique_ptr<Overlapped>> &list) {
            for (std::unique_ptr<Overlapped> overlapped = DeqOverlapped (list);
                    overlapped.get () != 0; overlapped = DeqOverlapped (list)) {
                while (1) {
                    ssize_t result = overlapped->Prolog (SharedPtr (this));
                    if (result > 0) {
                        if (overlapped->Epilog (SharedPtr (this))) {
                            return overlapped;
                        }
                    }
                    else if (result == 0) {
                        HandleDisconnect ();
                        return std::unique_ptr<Stream::Overlapped> ();
                    }
                    else {
                        THEKOGANS_UTIL_ERROR_CODE errorCode = overlapped->GetError ();
                        if (errorCode == EAGAIN || errorCode == EWOULDBLOCK) {
                            EnqOverlapped (std::move (overlapped), list, true);
                        }
                        else {
                            THEKOGANS_UTIL_ERROR_CODE_EXCEPTION exception (errorCode);
                            THEKOGANS_UTIL_EXCEPTION_NOTE_LOCATION (exception);
                            HandleError (exception);
                        }
                        return std::unique_ptr<Stream::Overlapped> ();
                    }
                }
            }
            return std::unique_ptr<Stream::Overlapped> ();
        }
    #endif // !defined (TOOLCHAIN_OS_Windows)

        void Stream::HandleOverlapped (Overlapped &overlapped) throw () {
            if (overlapped.GetType () == ReadOverlapped::TYPE) {
                ReadOverlapped &readOverlapped = (ReadOverlapped &)overlapped;
                util::Producer<StreamEvents>::Produce (
                    std::bind (
                        &StreamEvents::OnStreamRead,
                        std::placeholders::_1,
                        SharedPtr (this),
                        std::move (readOverlapped.buffer)));
            }
            else if (overlapped.GetType () == WriteOverlapped::TYPE) {
                WriteOverlapped &writeOverlapped = (WriteOverlapped &)overlapped;
                util::Producer<StreamEvents>::Produce (
                    std::bind (
                        &StreamEvents::OnStreamWrite,
                        std::placeholders::_1,
                        SharedPtr (this),
                        std::move (writeOverlapped.buffer)));
            }
        }

    } // namespace stream
} // namespace thekogans
