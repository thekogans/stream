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

#include "thekogans/util/Exception.h"
#include "thekogans/stream/NamedPipe.h"

namespace thekogans {
    namespace stream {

        THEKOGANS_STREAM_IMPLEMENT_STREAM (NamedPipe)

        bool NamedPipe::Wait (
                const std::string &name,
                DWORD timeout) {
            return WaitNamedPipeW (util::os::windows::UTF8ToUTF16 (name).c_str (), timeout) == TRUE;
        }

        NamedPipe::SharedPtr NamedPipe::CreateClientNamedPipe (
                const std::string &name,
                DWORD desiredAccess,
                DWORD shareMode,
                LPSECURITY_ATTRIBUTES securityAttributes,
                DWORD creationDisposition,
                DWORD flagsAndAttributes,
                HANDLE templateFile) {
            THEKOGANS_UTIL_HANDLE handle = CreateFileW (
                util::os::windows::UTF8ToUTF16 (name).c_str (),
                desiredAccess,
                shareMode,
                securityAttributes,
                creationDisposition,
                flagsAndAttributes | FILE_FLAG_OVERLAPPED,
                templateFile);
            if (handle == THEKOGANS_UTIL_INVALID_HANDLE_VALUE) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE);
            }
            return SharedPtr (new NamedPipe (handle));
        }

        NamedPipe::SharedPtr NamedPipe::CreateServerNamedPipe (
                const std::string &name,
                DWORD openMode,
                DWORD pipeMode,
                DWORD maxInstances,
                DWORD outBufferSize,
                DWORD inBufferSize,
                DWORD defaultTimeOut,
                LPSECURITY_ATTRIBUTES securityAttributes) {
            THEKOGANS_UTIL_HANDLE handle = CreateNamedPipeW (
                util::os::windows::UTF8ToUTF16 (name).c_str (),
                openMode | FILE_FLAG_OVERLAPPED,
                pipeMode,
                maxInstances,
                outBufferSize,
                inBufferSize,
                defaultTimeOut,
                securityAttributes);
            if (handle == THEKOGANS_UTIL_INVALID_HANDLE_VALUE) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE);
            }
            return SharedPtr (new NamedPipe (handle));
        }

        namespace {
            struct ReadOverlapped : public Overlapped {
                THEKOGANS_STREAM_DECLARE_OVERLAPPED (ReadOverlapped)

                util::Buffer::SharedPtr buffer;

                ReadOverlapped (std::size_t bufferLength) :
                    buffer (new util::Buffer (util::NetworkEndian, bufferLength)) {}

                virtual ssize_t Prolog (Stream::SharedPtr /*stream*/) throw () override {
                    return GetError () == ERROR_SUCCESS ? buffer->AdvanceWriteOffset (GetCount ()) : -1;
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

        void NamedPipe::Read (std::size_t bufferLength) {
            if (bufferLength > 0) {
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

                virtual ssize_t Prolog (Stream::SharedPtr /*stream*/) throw () override {
                    return GetError () == ERROR_SUCCESS ? buffer->AdvanceReadOffset (GetCount ()) : -1;
                }

                virtual bool Epilog (Stream::SharedPtr stream) throw () override {
                    stream->util::Producer<StreamEvents>::Produce (
                        std::bind (
                            &StreamEvents::OnStreamWrite,
                            std::placeholders::_1,
                            stream,
                            buffer));
                    return true;
                }

            };

            THEKOGANS_STREAM_IMPLEMENT_OVERLAPPED (WriteOverlapped)
        }

        void NamedPipe::Write (util::Buffer::SharedPtr buffer) {
            if (!buffer->IsEmpty ()) {
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
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        namespace {
            struct ConnectOverlapped : public Overlapped {
                THEKOGANS_STREAM_DECLARE_OVERLAPPED (ConnectOverlapped)

                ConnectOverlapped () {}

                virtual ssize_t Prolog (Stream::SharedPtr /*stream*/) throw () override {
                    return GetError () == ERROR_SUCCESS ? 1 : -1;
                }

                virtual bool Epilog (Stream::SharedPtr stream) throw () override {
                    NamedPipe::SharedPtr namedPipe = stream;
                    if (namedPipe != nullptr) {
                        namedPipe->util::Producer<NamedPipeEvents>::Produce (
                            std::bind (
                                &NamedPipeEvents::OnNamedPipeConnected,
                                std::placeholders::_1,
                                namedPipe));
                    }
                    return true;
                }
            };

            THEKOGANS_STREAM_IMPLEMENT_OVERLAPPED (ConnectOverlapped)
        }

        void NamedPipe::Connect () {
            Overlapped::SharedPtr overlapped (new ConnectOverlapped);
            if (!ConnectNamedPipe (handle, overlapped.Get ())) {
                THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_UTIL_OS_ERROR_CODE;
                if ((errorCode == ERROR_PIPE_CONNECTED &&
                        !PostQueuedCompletionStatus (
                            handle, 0, (ULONG_PTR)token.GetValue (), overlapped.Get ())) ||
                        errorCode != ERROR_IO_PENDING) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (errorCode);
                }
            }
            overlapped.Release ();
        }

        void NamedPipe::Disconnect (bool flushBuffers) {
            if ((flushBuffers && !FlushFileBuffers (handle)) || !DisconnectNamedPipe (handle)) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE);
            }
        }

        void NamedPipe::SetMode (DWORD pipeMode) {
            if (!SetNamedPipeHandleState (handle, &pipeMode, 0, 0)) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE);
            }
        }

        namespace {
            struct SecurityDescriptor : public SECURITY_DESCRIPTOR {
                SecurityDescriptor () {
                    InitializeSecurityDescriptor (
                        (SECURITY_DESCRIPTOR *)this, SECURITY_DESCRIPTOR_REVISION);
                    SetSecurityDescriptorDacl (
                        (SECURITY_DESCRIPTOR *)this, TRUE, 0, FALSE);
                }
            };

            struct SecurityAttributes : public SECURITY_ATTRIBUTES {
                SecurityDescriptor securityDescriptor;
                SecurityAttributes () {
                    memset ((SECURITY_ATTRIBUTES *)this, 0, sizeof (SECURITY_ATTRIBUTES));
                    nLength = sizeof (SECURITY_ATTRIBUTES);
                    lpSecurityDescriptor = &securityDescriptor;
                    bInheritHandle = FALSE;
                }
            };
        }

        LPSECURITY_ATTRIBUTES NamedPipe::DefaultSecurityAttributes () {
            static SecurityAttributes securityAttributes;
            return (LPSECURITY_ATTRIBUTES)&securityAttributes;
        }

    } // namespace stream
} // namespace thekogans

#endif // defined (TOOLCHAIN_OS_Windows)
