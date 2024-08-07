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
    #include <winsock2.h>
#else // defined (TOOLCHAIN_OS_Windows)
    #include <sys/ioctl.h>
    #include <arpa/inet.h>
    #include <net/if.h>
    #include <netinet/in.h>
    #if defined (TOOLCHAIN_OS_Linux)
        #include <stropts.h>
    #endif // defined (TOOLCHAIN_OS_Linux)
#endif // defined (TOOLCHAIN_OS_Windows)
#include <cstdio>
#include "thekogans/util/Flags.h"
#include "thekogans/util/Exception.h"
#include "thekogans/util/LoggerMgr.h"
#include "thekogans/util/StringUtils.h"
#include "thekogans/util/XMLUtils.h"
#include "thekogans/stream/Socket.h"

namespace thekogans {
    namespace stream {

    #if defined (TOOLCHAIN_OS_Windows)
        namespace {
            // This Windows specific initialization happens during
            // static ctor creation. No throwing here. If WSAStartup
            // fails, the clients will know soon enough when they
            // try to create sockets.
            struct WinSockInit {
                WinSockInit () {
                    WSADATA data;
                    WSAStartup (MAKEWORD (2, 2), &data);
                }
                ~WinSockInit () {
                    WSACleanup ();
                }
            } winSockInit;
        }
    #else // defined (TOOLCHAIN_OS_Windows)
        #define closesocket close
        #define ioctlsocket ioctl
    #endif // defined (TOOLCHAIN_OS_Windows)

        namespace {
            void SetNonBlocking (THEKOGANS_STREAM_SOCKET handle) {
                u_long arg = 1;
                if (ioctlsocket (handle, FIONBIO, &arg) == THEKOGANS_STREAM_SOCKET_ERROR) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
            }
        }

        Socket::Socket (THEKOGANS_UTIL_HANDLE handle) :
                Stream (handle) {
        #if defined (TOOLCHAIN_OS_Windows)
            WSAPROTOCOL_INFOW protocolInfo;
            socklen_t length = sizeof (WSAPROTOCOL_INFOW);
            if (getsockopt ((THEKOGANS_STREAM_SOCKET)handle, SOL_SOCKET, SO_PROTOCOL_INFO,
                    (char *)&protocolInfo, &length) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
            family = protocolInfo.iAddressFamily;
            type = protocolInfo.iSocketType;
            protocol = protocolInfo.iProtocol;
        #else // defined (TOOLCHAIN_OS_Windows)
            socklen_t length = sizeof (int);
        #if defined (TOOLCHAIN_OS_Linux)
            if (getsockopt (handle, SOL_SOCKET, SO_DOMAIN, &family, &length) ==
                    THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
        #elif defined (TOOLCHAIN_OS_OSX)
            // Asshole Apple does not provide a way of getting
            // socket family and protocol. This only works if
            // Bind was called on the handle. If you're not
            // calling this ctor explicitly, you have nothing
            // to worry about as it's only used in two places
            // by thekogans_stream; 1) Stream::StaticInit and
            // 2) TCPSocket::Accept. The first use is just to
            // instantiate a dummy socket, and the second will
            // work correctly as accept will do an implicit bind.
            // If you're calling this ctor explicitly you need to
            // make sure you either; 1) provide valid values or
            // 2) getsockname returns a valid address. Otherwise
            // your socket will return bad information for type
            // (GetType ()) and protocol (GetProtocol ()).
            {
                Address address;
                if (getsockname ((THEKOGANS_STREAM_SOCKET)handle, (sockaddr *)&address.storage,
                        &address.length) != THEKOGANS_STREAM_SOCKET_ERROR) {
                    family = address.storage.ss_family;
                }
            }
        #endif // defined (TOOLCHAIN_OS_Linux)
            if (getsockopt (handle, SOL_SOCKET, SO_TYPE, &type, &length) ==
                    THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
        #if defined (TOOLCHAIN_OS_Linux)
            if (getsockopt (handle, SOL_SOCKET, SO_PROTOCOL, &protocol, &length) ==
                    THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
        #elif defined (TOOLCHAIN_OS_OSX)
            protocol =
                type == SOCK_STREAM ? IPPROTO_TCP :
                (type == SOCK_DGRAM || type == SOCK_RAW) ? IPPROTO_UDP : 0;
        #endif // defined (TOOLCHAIN_OS_Linux)
        #endif // defined (TOOLCHAIN_OS_Windows)
            SetNonBlocking ((THEKOGANS_STREAM_SOCKET)handle);
        }

        Socket::Socket (
                int family_,
                int type_,
                int protocol_) :
                Stream (
                #if defined (TOOLCHAIN_OS_Windows)
                    (THEKOGANS_UTIL_HANDLE)WSASocketW (
                        family_, type_, protocol_, 0, 0, WSA_FLAG_OVERLAPPED)),
                #else // defined (TOOLCHAIN_OS_Windows)
                    (THEKOGANS_UTIL_HANDLE)socket (family_, type_, protocol_)),
                #endif // defined (TOOLCHAIN_OS_Windows)
                family (family_),
                type (type_),
                protocol (protocol_) {
            SetNonBlocking ((THEKOGANS_STREAM_SOCKET)handle);
        }

    #if defined (TOOLCHAIN_OS_Windows)
        Socket::~Socket () {
            Close ();
        }
    #endif // defined (TOOLCHAIN_OS_Windows)

        void Socket::Close () throw () {
            if (handle != THEKOGANS_UTIL_INVALID_HANDLE_VALUE) {
                closesocket ((THEKOGANS_STREAM_SOCKET)handle);
                handle = THEKOGANS_UTIL_INVALID_HANDLE_VALUE;
            #if !defined (TOOLCHAIN_OS_Windows)
                in.clear ();
                out.clear ();
            #endif // !defined (TOOLCHAIN_OS_Windows)
                family = -1;
                type = -1;
                protocol = -1;
            }
        }

        namespace {
            struct ReadOverlapped : public Overlapped {
                THEKOGANS_STREAM_DECLARE_OVERLAPPED (ReadOverlapped)

                std::size_t bufferLength;
                util::Buffer::SharedPtr buffer;
            #if defined (TOOLCHAIN_OS_Windows)
                WSABUF wsaBuf;
                DWORD flags;
            #endif // defined (TOOLCHAIN_OS_Windows)

                ReadOverlapped (std::size_t bufferLength_) :
                        bufferLength (bufferLength_),
                        buffer (new util::Buffer (util::NetworkEndian, bufferLength)) {
                #if defined (TOOLCHAIN_OS_Windows)
                    wsaBuf.len = (ULONG)buffer->GetDataAvailableForWriting ();
                    wsaBuf.buf = (char *)buffer->GetWritePtr ();
                    flags = 0;
                #endif // defined (TOOLCHAIN_OS_Windows)
                }

                virtual ssize_t Prolog (Stream::SharedPtr stream) throw () override {
                #if defined (TOOLCHAIN_OS_Windows)
                    if (GetError () != ERROR_SUCCESS) {
                        return -1;
                    }
                    buffer->AdvanceWriteOffset (GetCount ());
                #endif // defined (TOOLCHAIN_OS_Windows)
                    if (buffer->IsEmpty ()) {
                        // If passed in bufferLength was 0, than try to grab all available data.
                        if (bufferLength == 0) {
                            u_long value = 0;
                            if (ioctlsocket (
                                    (THEKOGANS_STREAM_SOCKET)stream->GetHandle (),
                                    FIONREAD, &value) == THEKOGANS_STREAM_SOCKET_ERROR) {
                                SetError (THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                                return -1;
                            }
                        #if !defined (TOOLCHAIN_OS_Windows)
                            if (value == 0) {
                                SetError (EWOULDBLOCK);
                                return -1;
                            }
                        #endif // !defined (TOOLCHAIN_OS_Windows)
                            buffer->Resize ((std::size_t)value);
                        #if defined (TOOLCHAIN_OS_Windows)
                            wsaBuf.len = (ULONG)buffer->GetDataAvailableForWriting ();
                            wsaBuf.buf = (char *)buffer->GetWritePtr ();
                            flags = 0;
                        #endif // defined (TOOLCHAIN_OS_Windows)
                        }
                    #if defined (TOOLCHAIN_OS_Windows)
                        DWORD countRead = 0;
                        if (WSARecv (
                                (THEKOGANS_STREAM_SOCKET)stream->GetHandle (),
                                &wsaBuf,
                                1,
                                &countRead,
                                &flags,
                                0,
                                0) == THEKOGANS_STREAM_SOCKET_ERROR) {
                    #else // defined (TOOLCHAIN_OS_Windows)
                        ssize_t countRead = recv (
                            stream->GetHandle (),
                            (char *)buffer->GetWritePtr (),
                            buffer->GetDataAvailableForWriting (),
                            0);
                        if (countRead == THEKOGANS_STREAM_SOCKET_ERROR) {
                    #endif // defined (TOOLCHAIN_OS_Windows)
                            SetError (THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                            SetCount (0);
                            return -1;
                        }
                        SetError (0);
                        SetCount (countRead);
                        buffer->AdvanceWriteOffset ((std::size_t)countRead);
                    }
                    return buffer->GetDataAvailableForReading ();
                }

                virtual bool Epilog (Stream::SharedPtr stream) throw () override {
                    stream->util::Producer<StreamEvents>::Produce (
                        std::bind (
                            &StreamEvents::OnStreamRead,
                            std::placeholders::_1,
                            stream,
                            buffer));
                    if (stream->IsChainRead ()) {
                        stream->Read (bufferLength);
                    }
                    return true;
                }
            };

            THEKOGANS_STREAM_IMPLEMENT_OVERLAPPED (ReadOverlapped)
        }

        void Socket::Read (std::size_t bufferLength) {
        #if defined (TOOLCHAIN_OS_Windows)
            ReadOverlapped::SharedPtr overlapped (new ReadOverlapped (bufferLength));
            if (WSARecv (
                    (THEKOGANS_STREAM_SOCKET)handle,
                    &overlapped->wsaBuf,
                    1,
                    0,
                    &overlapped->flags,
                    overlapped.Get (),
                    0) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_STREAM_SOCKET_ERROR_CODE;
                if (errorCode != WSA_IO_PENDING) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (errorCode);
                }
            }
            overlapped.Release ();
        #else // defined (TOOLCHAIN_OS_Windows)
            EnqOverlapped (new ReadOverlapped (bufferLength), in);
        #endif // defined (TOOLCHAIN_OS_Windows)
        }

        namespace {
            struct WriteOverlapped : public Overlapped {
                THEKOGANS_STREAM_DECLARE_OVERLAPPED (WriteOverlapped)

                util::Buffer::SharedPtr buffer;
            #if defined (TOOLCHAIN_OS_Windows)
                WSABUF wsaBuf;
            #endif // defined (TOOLCHAIN_OS_Windows)

                WriteOverlapped (util::Buffer::SharedPtr buffer_) :
                        buffer (buffer_) {
                #if defined (TOOLCHAIN_OS_Windows)
                    wsaBuf.len = (ULONG)buffer->GetDataAvailableForReading ();
                    wsaBuf.buf = (char *)buffer->GetReadPtr ();
                #endif // defined (TOOLCHAIN_OS_Windows)
                }

                ssize_t Prolog (Stream::SharedPtr stream) throw () override {
                #if defined (TOOLCHAIN_OS_Windows)
                    return GetError () == ERROR_SUCCESS ? buffer->AdvanceReadOffset (GetCount ()) : -1;
                #else // defined (TOOLCHAIN_OS_Windows)
                    ssize_t countWritten = send (
                        stream->GetHandle (),
                        buffer->GetReadPtr (),
                        buffer->GetDataAvailableForReading (),
                        0);
                    if (countWritten == THEKOGANS_STREAM_SOCKET_ERROR) {
                        SetError (THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                        SetCount (0);
                        return -1;
                    }
                    SetError (0);
                    SetCount (countWritten);
                    return buffer->AdvanceReadOffset ((std::size_t)countWritten);
                #endif // defined (TOOLCHAIN_OS_Windows)
                }

                virtual bool Epilog (Stream::SharedPtr stream) throw () override {
                    if (buffer->IsEmpty ()) {
                        stream->util::Producer<StreamEvents>::Produce (
                            std::bind (
                                &StreamEvents::OnStreamWrite,
                                std::placeholders::_1,
                                stream,
                                buffer));
                    }
                    return buffer->IsEmpty ();
                }
            };

            THEKOGANS_STREAM_IMPLEMENT_OVERLAPPED (WriteOverlapped)
        }

        void Socket::Write (util::Buffer::SharedPtr buffer) {
            if (!buffer->IsEmpty ()) {
            #if defined (TOOLCHAIN_OS_Windows)
                WriteOverlapped::SharedPtr overlapped (new WriteOverlapped (buffer));
                if (WSASend (
                        (THEKOGANS_STREAM_SOCKET)handle,
                        &overlapped->wsaBuf,
                        1,
                        0,
                        0,
                        overlapped.Get (),
                        0) == THEKOGANS_STREAM_SOCKET_ERROR) {
                    THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_STREAM_SOCKET_ERROR_CODE;
                    if (errorCode != WSA_IO_PENDING) {
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

        bool Socket::IsBound () const {
            Address address;
            return getsockname ((THEKOGANS_STREAM_SOCKET)handle,
                (sockaddr *)&address.storage, &address.length) == 0;
        }

        void Socket::Bind (const Address &address) {
            if (bind ((THEKOGANS_STREAM_SOCKET)handle, &address.address,
                    address.length) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
        }

        Address Socket::GetHostAddress () const {
            Address address;
            if (getsockname ((THEKOGANS_STREAM_SOCKET)handle,
                    &address.address, &address.length) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
            return address;
        }

        Address Socket::GetPeerAddress () const {
            Address address;
            if (getpeername ((THEKOGANS_STREAM_SOCKET)handle,
                    &address.address, &address.length) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
            return address;
        }

        bool Socket::IsIPV6Only () const {
            int arg = 0;
            socklen_t length = sizeof (arg);
            if (getsockopt ((THEKOGANS_STREAM_SOCKET)handle, IPPROTO_IPV6,
                    IPV6_V6ONLY, (char *)&arg, &length) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
            return arg == 1;
        }

        void Socket::SetIPV6Only (bool ipv6Only) {
            u_long arg = ipv6Only ? 1 : 0;
            if (setsockopt ((THEKOGANS_STREAM_SOCKET)handle, IPPROTO_IPV6,
                    IPV6_V6ONLY, (char *)&arg, sizeof (arg)) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
        }

        bool Socket::IsReuseAddress () const {
            int arg = 0;
            socklen_t length = sizeof (arg);
            if (getsockopt ((THEKOGANS_STREAM_SOCKET)handle, SOL_SOCKET,
                    SO_REUSEADDR, (char *)&arg, &length) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
            return arg == 1;
        }

        void Socket::SetReuseAddress (bool reuseAddress) {
            u_long arg = reuseAddress ? 1 : 0;
            if (setsockopt ((THEKOGANS_STREAM_SOCKET)handle, SOL_SOCKET,
                    SO_REUSEADDR, (char *)&arg, sizeof (arg)) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
        }

    #if defined (SO_EXCLUSIVEADDRUSE)
        bool Socket::IsExclusiveAddressUse () const {
            int arg = 0;
            socklen_t length = sizeof (arg);
            if (getsockopt ((THEKOGANS_STREAM_SOCKET)handle, SOL_SOCKET,
                    SO_EXCLUSIVEADDRUSE, (char *)&arg, &length) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
            return arg == 1;
        }

        void Socket::SetExclusiveAddressUse (bool exclusiveAddressUse) {
            u_long arg = exclusiveAddressUse ? 1 : 0;
            if (setsockopt ((THEKOGANS_STREAM_SOCKET)handle, SOL_SOCKET,
                    SO_EXCLUSIVEADDRUSE, (char *)&arg, sizeof (arg)) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
        }
    #endif // defined (SO_EXCLUSIVEADDRUSE)

    #if defined (SO_REUSEPORT) || defined (SO_REUSE_UNICASTPORT)
        bool Socket::IsReusePort () const {
        #if defined (SO_REUSE_UNICASTPORT)
            DWORD arg = 0;
            socklen_t length = sizeof (arg);
            if (getsockopt ((THEKOGANS_STREAM_SOCKET)handle, SOL_SOCKET,
                    SO_REUSE_UNICASTPORT, (char *)&arg, &length) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
            return arg == 1;
        #else // defined (SO_REUSE_UNICASTPORT)
            int arg = 0;
            socklen_t length = sizeof (arg);
            if (getsockopt ((THEKOGANS_STREAM_SOCKET)handle, SOL_SOCKET,
                    SO_REUSEPORT, (char *)&arg, &length) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
            return arg == 1;
        #endif // defined (SO_REUSE_UNICASTPORT)
        }

        void Socket::SetReusePort (bool reusePort) {
        #if defined (SO_REUSE_UNICASTPORT)
            DWORD arg = reusePort ? 1 : 0;
            if (setsockopt ((THEKOGANS_STREAM_SOCKET)handle, SOL_SOCKET,
                    SO_REUSE_UNICASTPORT, (char *)&arg, sizeof (arg)) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
        #else // defined (SO_REUSE_UNICASTPORT)
            u_long arg = reusePort ? 1 : 0;
            if (setsockopt ((THEKOGANS_STREAM_SOCKET)handle, SOL_SOCKET,
                    SO_REUSEPORT, (char *)&arg, sizeof (arg)) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
        #endif // defined (SO_REUSE_UNICASTPORT)
        }
    #endif // defined (SO_REUSEPORT) || defined (SO_REUSE_UNICASTPORT)

        std::size_t Socket::GetSendBufferSize () const {
            util::ui32 size = 0;
            socklen_t length = sizeof (size);
            if (getsockopt ((THEKOGANS_STREAM_SOCKET)handle, SOL_SOCKET,
                    SO_SNDBUF, (char *)&size, &length) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
            return size;
        }

        void Socket::SetSendBufferSize (std::size_t size) {
            util::ui32 value = (util::ui32)size;
            if (setsockopt ((THEKOGANS_STREAM_SOCKET)handle, SOL_SOCKET,
                    SO_SNDBUF, (char *)&value, sizeof (value)) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
        }

        std::size_t Socket::GetReceiveBufferSize () const {
            util::ui32 size = 0;
            socklen_t length = sizeof (size);
            if (getsockopt ((THEKOGANS_STREAM_SOCKET)handle, SOL_SOCKET,
                    SO_RCVBUF, (char *)&size, &length) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
            return size;
        }

        void Socket::SetReceiveBufferSize (std::size_t size) {
            util::ui32 value = (util::ui32)size;
            if (setsockopt ((THEKOGANS_STREAM_SOCKET)handle, SOL_SOCKET,
                    SO_RCVBUF, (char *)&value, sizeof (value)) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
        }

        THEKOGANS_UTIL_ERROR_CODE Socket::GetErrorCode () const {
            THEKOGANS_UTIL_ERROR_CODE errorCode = 0;
            socklen_t length = sizeof (errorCode);
            if (getsockopt ((THEKOGANS_STREAM_SOCKET)handle, SOL_SOCKET, SO_ERROR,
                    (char *)&errorCode, &length) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
            return errorCode;
        }

    } // namespace stream
} // namespace thekogans
