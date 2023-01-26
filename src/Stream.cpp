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
                    // The ReadOverlapped ctor will resize the buffer
                    // using the bufferLength that was passed in. If
                    // that value was 0, than try to grab all
                    // available data.
                    if (buffer.GetLength () == 0) {
                        buffer.Resize (stream->GetDataAvailableForReading ());
                    }
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
            if (handle != THEKOGANS_UTIL_INVALID_HANDLE_VALUE) {
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
                Close ();
            }
            THEKOGANS_UTIL_CATCH_AND_LOG_SUBSYSTEM (THEKOGANS_STREAM)
        }

        void Stream::Close () {
            if (handle != THEKOGANS_UTIL_INVALID_HANDLE_VALUE) {
            #if defined (TOOLCHAIN_OS_Windows)
                if (!::CloseHandle (handle)) {
            #else // defined (TOOLCHAIN_OS_Windows)
                if (close (handle) < 0) {
            #endif // defined (TOOLCHAIN_OS_Windows)
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_UTIL_OS_ERROR_CODE);
                }
                handle = THEKOGANS_UTIL_INVALID_HANDLE_VALUE;
            }
        }

        void Stream::Write (
                const void *buffer,
                std::size_t bufferLength) {
            if (buffer != 0 && bufferLength > 0) {
                util::Buffer buffer_ (
                    util::NetworkEndian,
                    (const util::ui8 *)buffer,
                    (const util::ui8 *)buffer + bufferLength);
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
            std::unique_ptr<Overlapped> overlapped;
            THEKOGANS_UTIL_TRY {
                util::LockGuard<util::SpinLock> guard (spinLock);
                if (!list.empty ()) {
                    overlapped = std::move (list.front ());
                    list.pop_front ();
                    if (list.empty ()) {
                        AsyncIoEventQueue::Instance ().SetStreamEventMask (*this);
                    }
                }
            }
            THEKOGANS_UTIL_CATCH (util::Exception) {
                THEKOGANS_UTIL_EXCEPTION_NOTE_LOCATION (exception);
                HandleError (exception);
            }
            return overlapped;
        }
    #endif // !defined (TOOLCHAIN_OS_Windows)

    #if defined (TOOLCHAIN_OS_Windows)
        namespace {
            #define STATUS_CANCELED 0xC0000120
            #define STATUS_LOCAL_DISCONNECT 0xC000013B
            #define STATUS_REMOTE_DISCONNECT 0xC000013C
            #define STATUS_PIPE_BROKEN 0xC000014b
            #define STATUS_CONNECTION_RESET 0xC000020D

            std::string ErrorCodeTostring (THEKOGANS_UTIL_ERROR_CODE errorCode) {
                return
                    errorCode == STATUS_CANCELED ? "STATUS_CANCELED" :
                    errorCode == STATUS_LOCAL_DISCONNECT ? "STATUS_LOCAL_DISCONNECT" :
                    errorCode == STATUS_REMOTE_DISCONNECT ? "STATUS_REMOTE_DISCONNECT" :
                    errorCode == STATUS_PIPE_BROKEN ? "STATUS_PIPE_BROKEN" :
                    errorCode == STATUS_CONNECTION_RESET ? "STATUS_CONNECTION_RESET" :
                    util::FormatString ("Unknown code: %x", errorCode);
            }
        }
    #endif // defined (TOOLCHAIN_OS_Windows)

        bool Stream::ExecOverlapped (
                std::unique_ptr<Overlapped> overlapped
            #if !defined (TOOLCHAIN_OS_Windows)
                , std::list<std::unique_ptr<Overlapped>> &list
            #endif // !defined (TOOLCHAIN_OS_Windows)
                ) {
            if (overlapped.get () != 0) {
                while (1) {
                    ssize_t result = overlapped->Prolog (SharedPtr (this));
                    if (result > 0) {
                        if (overlapped->Epilog (SharedPtr (this))) {
                            HandleOverlapped (*overlapped);
                            return true;
                        }
                    }
                    else if (result == 0) {
                        HandleDisconnect ();
                        return false;
                    }
                    else {
                        THEKOGANS_UTIL_ERROR_CODE errorCode = overlapped->GetError ();
                    #if defined (TOOLCHAIN_OS_Windows)
                        // Convert known errors to disconnect events.
                        if (errorCode == STATUS_LOCAL_DISCONNECT ||
                                errorCode == STATUS_REMOTE_DISCONNECT ||
                                errorCode == STATUS_PIPE_BROKEN ||
                                errorCode == STATUS_CONNECTION_RESET) {
                            HandleDisconnect ();
                        }
                        else if (errorCode != STATUS_CANCELED) {
                    #else // defined (TOOLCHAIN_OS_Windows)
                        if (errorCode == EAGAIN || errorCode == EWOULDBLOCK) {
                            EnqOverlapped (std::move (overlapped), list, true);
                        }
                        else {
                    #endif // defined (TOOLCHAIN_OS_Windows)
                            HandleError (THEKOGANS_UTIL_ERROR_CODE_EXCEPTION (errorCode));
                        }
                        return false;
                    }
                }
            }
            return false;
        }

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
