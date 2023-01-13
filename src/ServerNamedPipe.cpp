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
#include "thekogans/stream/ServerNamedPipe.h"

namespace thekogans {
    namespace stream {

        namespace {
            inline THEKOGANS_UTIL_HANDLE CreateNamedPipe (
                    LPCWSTR name,
                    DWORD openMode,
                    DWORD pipeMode,
                    DWORD maxInstances,
                    DWORD outBufferSize,
                    DWORD inBufferSize,
                    DWORD defaultTimeOut,
                    LPSECURITY_ATTRIBUTES securityAttributes) {
                if (name != 0) {
                    THEKOGANS_UTIL_HANDLE handle = CreateNamedPipeW (
                        name,
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
                    return handle;
                }
                else {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
                }
            }
        }

        ServerNamedPipe::ServerNamedPipe (
            LPCWSTR name_,
            DWORD openMode_,
            DWORD pipeMode_,
            DWORD maxInstances_,
            DWORD outBufferSize_,
            DWORD inBufferSize_,
            DWORD defaultTimeOut_,
            LPSECURITY_ATTRIBUTES securityAttributes_) :
            Stream (
                CreateNamedPipe (
                    name_,
                    openMode_,
                    pipeMode_,
                    maxInstances_,
                    outBufferSize_,
                    inBufferSize_,
                    defaultTimeOut_,
                    securityAttributes_)),
            name (name_),
            openMode (openMode_),
            pipeMode (pipeMode_),
            maxInstances (maxInstances_),
            outBufferSize (outBufferSize_),
            inBufferSize (inBufferSize_),
            defaultTimeOut (defaultTimeOut_),
            securityAttributes (securityAttributes_) {}

        namespace {
            struct ConnectOverlapped : public Stream::Overlapped {
                THEKOGANS_STREAM_DECLARE_STREAM_OVERLAPPED (ConnectOverlapped)

                virtual ssize_t Prolog (Stream::SharedPtr /*stream*/) {
                    return GetError () == ERROR_SUCCESS ? 1 : -1;
                }
            };

            THEKOGANS_STREAM_IMPLEMENT_STREAM_OVERLAPPED (ConnectOverlapped)
        }

        void ServerNamedPipe::Connect () {
            THEKOGANS_UTIL_TRY {
                std::unique_ptr<Overlapped> overlapped (new ConnectOverlapped);
                if (!ConnectNamedPipe (handle, overlapped.get ())) {
                    THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_UTIL_OS_ERROR_CODE;
                    if ((errorCode == ERROR_PIPE_CONNECTED &&
                            !PostQueuedCompletionStatus (handle, 0, (ULONG_PTR)token, overlapped.get ())) ||
                            errorCode != ERROR_IO_PENDING) {
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

        void ServerNamedPipe::Disconnect (bool flushBuffers) {
            if ((flushBuffers && !FlushFileBuffers (handle)) || !DisconnectNamedPipe (handle)) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE);
            }
        }

        void ServerNamedPipe::HandleOverlapped (Overlapped &overlapped) throw () {
            if (overlapped.GetName () == ConnectOverlapped::NAME) {
                util::Producer<ServerNamedPipeEvents>::Produce (
                    std::bind (
                        &ServerNamedPipeEvents::OnServerNamedPipeConnected,
                        std::placeholders::_1,
                        SharedPtr (this)));
            }
            else {
                NamedPipe::HandleOverlapped (overlapped);
            }
        }

        namespace {
            struct SecurityDescriptor : public SECURITY_DESCRIPTOR {
                SecurityDescriptor () {
                    InitializeSecurityDescriptor ((SECURITY_DESCRIPTOR *)this, SECURITY_DESCRIPTOR_REVISION);
                    SetSecurityDescriptorDacl ((SECURITY_DESCRIPTOR *)this, TRUE, 0, FALSE);
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
            }
        }

        LPSECURITY_ATTRIBUTES ServerNamedPipe::DefaultSecurityAttributes () {
            static SecurityAttributes securityAttributes;
            return (LPSECURITY_ATTRIBUTES)&securityAttributes;
        }

    } // namespace stream
} // namespace thekogans

#endif // defined (TOOLCHAIN_OS_Windows)
