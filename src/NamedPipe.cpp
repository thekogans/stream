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
#include "thekogans/stream/NamedPipe.h"

namespace thekogans {
    namespace stream {

        namespace {
            inline THEKOGANS_UTIL_HANDLE CreateNamedPipe () {
                SECURITY_DESCRIPTOR sd;
                InitializeSecurityDescriptor (&sd, SECURITY_DESCRIPTOR_REVISION);
                SetSecurityDescriptorDacl (&sd, TRUE, 0, FALSE);
                SECURITY_ATTRIBUTES sa;
                sa.nLength = sizeof (SECURITY_ATTRIBUTES);
                sa.lpSecurityDescriptor = &sd;
                sa.bInheritHandle = FALSE;
                DWORD dwPipeMode = PIPE_WAIT;
                if (pipeType == Byte) {
                    dwPipeMode |= PIPE_TYPE_BYTE | PIPE_READMODE_BYTE;
                }
                else {
                    dwPipeMode |= PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE;
                }
                handle = CreateNamedPipeW (
                    path,
                    PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                    dwPipeMode,
                    PIPE_UNLIMITED_INSTANCES,
                    bufferSize,
                    bufferSize,
                    INFINITE,
                    &sa);
                if (handle == THEKOGANS_UTIL_INVALID_HANDLE_VALUE) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_UTIL_OS_ERROR_CODE);
                }
                return handle;
            }
        }

        ServerNamedPipe::ServerNamedPipe (
            const Address &address_,
            PipeType pipeType_) :
            Stream (
                CreateNamedPipe (
                    util::UTF8ToUTF16 (address.GetPath ()).c_str (),
                    pipeType_),
                address (address_),
                pipeType (pipeType_) {}

        namespace {
            inline THEKOGANS_UTIL_HANDLE CreateFile (
                    const char *path,
                    LPSECURITY_ATTRIBUTES securityAttributes) {
                THEKOGANS_UTIL_HANDLE handle = CreateFileW (
                    path,
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    securityAttributes,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                    0);
                if (handle == THEKOGANS_UTIL_INVALID_HANDLE_VALUE) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_UTIL_OS_ERROR_CODE);
                }
                return handle;
            }
        }

        void NamedPipe::NamedPipe (
                const Address &address_,
                PipeType pipeType_,
                LPSECURITY_ATTRIBUTES securityAttributes) :
                Stream (
                    CreateFile (
                        util::UTF8ToUTF16 (address.GetPath ()).c_str (),
                        securityAttributes)),
                address (address_),
                pipeType (pipeType_) {
            if (pipeType == Message) {
                DWORD dwMode = PIPE_READMODE_MESSAGE;
                if (!SetNamedPipeHandleState (handle, &dwMode, 0, 0)) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_UTIL_OS_ERROR_CODE);
                }
            }
        }

        std::size_t NamedPipe::GetDataAvailable () const {
            DWORD totalBytesAvailable = 0;
            if (!PeekNamedPipe (handle, 0, 0, 0, &totalBytesAvailable, 0)) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE);
            }
            return totalBytesAvailable;
        }

        void NamedPipe::Read (std::size_t bufferLength) {
            if (bufferLength != 0) {
                THEKOGANS_UTIL_TRY {
                    std::unique_ptr<ReadOverlapped> overlapped (
                        new ReadOverlapped (bufferLength));
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

        void NamedPipe::Write (util::Buffer buffer) {
            if (!buffer.IsEmpty ()) {
                THEKOGANS_UTIL_TRY {
                    std::unique_ptr<WriteOverlapped> overlapped (
                        new WriteOverlapped (std::move (buffer)));
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

        void NamedPipe::Accept () {
            THEKOGANS_UTIL_TRY {
                std::unique_ptr<Overlapped> overlapped (new AcceptOverlapped);
                if (!ConnectNamedPipe (handle, overlapped.get ())) {
                    THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_UTIL_OS_ERROR_CODE;
                    if (errorCode == ERROR_PIPE_CONNECTED) {
                        HandleOverlapped (*overlapped);
                        return;
                    }
                    else if (errorCode != ERROR_IO_PENDING) {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (errorCode);
                    }
                }
                overlapped.release ();
            }
            THEKOGANS_UTIL_CATCH (util::Exception) {
                THEKOGANS_UTIL_EXCEPTION_NOTE_LOCATION (exception);
                HandleError (exception);
            }
        }

        void NamedPipe::Disconnect (bool flushBuffers) {
            if ((flushBuffers && !FlushFileBuffers (handle)) || !DisconnectNamedPipe (handle)) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE);
            }
        }

        bool ClientNamedPipe::Wait (DWORD timeout) {
            return WaitNamedPipeW (
                util::UTF8ToUTF16 (address.GetPath ()).c_str (),
                timeout) == TRUE;
        }

        NamedPipe::SharedPtr NamedPipe::Clone () const {
            return NamedPipe::SharedPtr (new NamedPipe (address, pipeType));
        }

        void NamedPipe::HandleOverlapped (Overlapped &overlapped) throw () {
            if (overlapped.GetName () == AcceptOverlapped::NAME) {
                util::Producer<NamedPipeEvents>::Produce (
                    std::bind (
                        &NamedPipeEvents::OnNamedPipeAccept,
                        std::placeholders::_1,
                        SharedPtr (this)));
            }
            else {
                Stream::HandleOverlapped (overlapped);
            }
        }

        std::size_t NamedPipe::ReadHelper (
                void *buffer,
                std::size_t count) {
            if (buffer != 0 && count > 0) {
                DWORD countRead = 0;
                if (!ReadFile (handle, buffer, (DWORD)count, &countRead, 0)) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_UTIL_OS_ERROR_CODE);
                }
                return countRead;
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        std::size_t NamedPipe::WriteHelper (
                const void *buffer,
                std::size_t count) {
            if (buffer != 0 && count > 0) {
                DWORD countWritten = 0;
                if (!WriteFile (handle, buffer, (DWORD)count, &countWritten, 0)) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_UTIL_OS_ERROR_CODE);
                }
                return countWritten;
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

    } // namespace stream
} // namespace thekogans

#endif // defined (TOOLCHAIN_OS_Windows)
