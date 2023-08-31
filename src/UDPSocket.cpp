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
        #include <windows.h.>
    #endif // !defined (_WINDOWS_)
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <ws2ipdef.h>
    #include <iphlpapi.h>
#else // defined (TOOLCHAIN_OS_Windows)
    #include <sys/ioctl.h>
    #include <ifaddrs.h>
    #include <net/if.h>
    #if defined (TOOLCHAIN_OS_OSX)
        #define __APPLE_USE_RFC_3542
    #endif // defined (TOOLCHAIN_OS_OSX)
    #include <netinet/in.h>
#endif // defined (TOOLCHAIN_OS_Windows)
#include <cassert>
#include "thekogans/util/Exception.h"
#include "thekogans/stream/MsgHdr.h"
#include "thekogans/stream/Overlapped.h"
#include "thekogans/stream/UDPSocket.h"

namespace thekogans {
    namespace stream {

        THEKOGANS_UTIL_IMPLEMENT_HEAP_WITH_LOCK (UDPSocket, util::SpinLock)

    #if defined (TOOLCHAIN_OS_Windows)
        namespace {
            struct WindowsFunctions : public util::Singleton<WindowsFunctions, util::SpinLock> {
                LPFN_WSARECVMSG WSARecvMsg;
                LPFN_WSASENDMSG WSASendMsg;

                WindowsFunctions () :
                        WSARecvMsg (0),
                        WSASendMsg (0) {
                    struct Socket {
                        THEKOGANS_STREAM_SOCKET handle;
                        Socket () :
                                handle (WSASocketW (AF_INET, SOCK_STREAM, IPPROTO_TCP,
                                    0, 0, WSA_FLAG_OVERLAPPED)) {
                            if (handle == THEKOGANS_STREAM_INVALID_SOCKET) {
                                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                            }
                        }
                        ~Socket () {
                            closesocket (handle);
                        }
                    } socket;
                    {
                        GUID GuidWSARecvMsg = WSAID_WSARECVMSG;
                        DWORD bytesReturned = 0;
                        if (WSAIoctl (socket.handle,
                                SIO_GET_EXTENSION_FUNCTION_POINTER,
                                &GuidWSARecvMsg, sizeof (GuidWSARecvMsg),
                                &WSARecvMsg, sizeof (WSARecvMsg),
                                &bytesReturned, 0, 0) == THEKOGANS_STREAM_SOCKET_ERROR) {
                            THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                                THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                        }
                    }
                    {
                        GUID GuidWSASendMsg = WSAID_WSASENDMSG;
                        DWORD bytesReturned = 0;
                        if (WSAIoctl (socket.handle,
                                SIO_GET_EXTENSION_FUNCTION_POINTER,
                                &GuidWSASendMsg, sizeof (GuidWSASendMsg),
                                &WSASendMsg, sizeof (WSASendMsg),
                                &bytesReturned, 0, 0) == THEKOGANS_STREAM_SOCKET_ERROR) {
                            THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                                THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                        }
                    }
                }
            };
        }
    #else // defined (TOOLCHAIN_OS_Windows)
        #define ioctlsocket ioctl
    #endif // defined (TOOLCHAIN_OS_Windows)

        UDPSocket::UDPSocket (const Address &address) :
                Socket (address.GetFamily (), SOCK_DGRAM, 0) {
            Bind (address);
        }

        namespace {
            struct ReadFromOverlapped : public Overlapped {
                THEKOGANS_STREAM_DECLARE_OVERLAPPED (ReadFromOverlapped)

            public:
                std::size_t bufferLength;
                util::Buffer buffer;
            #if defined (TOOLCHAIN_OS_Windows)
                WSABUF wsaBuf;
                DWORD flags;
            #endif // defined (TOOLCHAIN_OS_Windows)
                Address address;

                ReadFromOverlapped (std::size_t bufferLength_) :
                        bufferLength (bufferLength_),
                        buffer (util::NetworkEndian, bufferLength) {
                #if defined (TOOLCHAIN_OS_Windows)
                    wsaBuf.len = (ULONG)buffer.GetDataAvailableForWriting ();
                    wsaBuf.buf = (char *)buffer.GetWritePtr ();
                    flags = 0;
                #endif // defined (TOOLCHAIN_OS_Windows)
                }

                virtual ssize_t Prolog (Stream &stream) throw () override {
                #if defined (TOOLCHAIN_OS_Windows)
                    if (GetError () != ERROR_SUCCESS) {
                        return -1;
                    }
                    buffer.AdvanceWriteOffset (GetCount ());
                #endif // defined (TOOLCHAIN_OS_Windows)
                    if (buffer.IsEmpty ()) {
                        // If passed in bufferLength was 0, than try to grab all available data.
                        if (bufferLength == 0) {
                            u_long countAvailable = 0;
                            if (ioctlsocket ((THEKOGANS_STREAM_SOCKET)stream.GetHandle (), FIONREAD, &countAvailable) ==
                                    THEKOGANS_STREAM_SOCKET_ERROR) {
                                SetError (THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                                return -1;
                            }
                        #if !defined (TOOLCHAIN_OS_Windows)
                            if (countAvailable == 0) {
                                SetError (EWOULDBLOCK);
                                return -1;
                            }
                        #endif // !defined (TOOLCHAIN_OS_Windows)
                            buffer.Resize ((std::size_t)countAvailable);
                        #if defined (TOOLCHAIN_OS_Windows)
                            wsaBuf.len = (ULONG)buffer.GetDataAvailableForWriting ();
                            wsaBuf.buf = (char *)buffer.GetWritePtr ();
                            flags = 0;
                        #endif // defined (TOOLCHAIN_OS_Windows)
                        }
                    #if defined (TOOLCHAIN_OS_Windows)
                        DWORD countRead = 0;
                        if (WSARecvFrom (
                                (THEKOGANS_STREAM_SOCKET)stream.GetHandle (),
                                &wsaBuf,
                                1,
                                &countRead,
                                &flags,
                                &address.address,
                                &address.length,
                                0,
                                0) == THEKOGANS_STREAM_SOCKET_ERROR) {
                    #else // defined (TOOLCHAIN_OS_Windows)
                        ssize_t countRead = recvfrom (
                            stream.GetHandle (),
                            (char *)buffer.GetWritePtr (),
                            buffer.GetDataAvailableForWriting (),
                            0,
                            &address.address,
                            &address.length);
                        if (countRead == THEKOGANS_STREAM_SOCKET_ERROR) {
                    #endif // defined (TOOLCHAIN_OS_Windows)
                            SetError (THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                            SetCount (0);
                            return -1;
                        }
                        SetError (0);
                        SetCount (countRead);
                        buffer.AdvanceWriteOffset ((std::size_t)countRead);
                    }
                    return buffer.GetDataAvailableForReading ();
                }

                virtual bool Epilog (Stream &stream) throw () override {
                    if (stream.IsChainRead ()) {
                        dynamic_cast<UDPSocket *> (&stream)->ReadFrom (bufferLength);
                    }
                    return true;
                }
            };

            THEKOGANS_STREAM_IMPLEMENT_OVERLAPPED (ReadFromOverlapped)
        }

        void UDPSocket::ReadFrom (std::size_t bufferLength) {
        #if defined (TOOLCHAIN_OS_Windows)
            ReadFromOverlapped::UniquePtr overlapped (new ReadFromOverlapped (bufferLength));
            if (WSARecvFrom ((THEKOGANS_STREAM_SOCKET)handle,
                    &overlapped->wsaBuf,
                    1,
                    0,
                    &overlapped->flags,
                    &overlapped->address.address,
                    &overlapped->address.length,
                    overlapped.get (),
                    0) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_STREAM_SOCKET_ERROR_CODE;
                if (errorCode != WSA_IO_PENDING) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (errorCode);
                }
            }
            overlapped.release ();
        #else // defined (TOOLCHAIN_OS_Windows)
            EnqOverlapped (
                Overlapped::UniquePtr (new ReadFromOverlapped (bufferLength)),
                in);
        #endif // defined (TOOLCHAIN_OS_Windows)
        }

        namespace {
            struct WriteToOverlapped : public Overlapped {
                THEKOGANS_STREAM_DECLARE_OVERLAPPED (WriteToOverlapped)

            public:
                util::Buffer buffer;
            #if defined (TOOLCHAIN_OS_Windows)
                WSABUF wsaBuf;
            #endif // defined (TOOLCHAIN_OS_Windows)
                Address address;

                WriteToOverlapped (
                        util::Buffer buffer_,
                        const Address &address_) :
                        buffer (std::move (buffer_)),
                        address (address_) {
                #if defined (TOOLCHAIN_OS_Windows)
                    wsaBuf.len = (ULONG)buffer.GetDataAvailableForReading ();
                    wsaBuf.buf = (char *)buffer.GetReadPtr ();
                #endif // defined (TOOLCHAIN_OS_Windows)
                }

                virtual ssize_t Prolog (Stream &stream) throw () override {
                #if defined (TOOLCHAIN_OS_Windows)
                    return GetError () == ERROR_SUCCESS ? buffer.AdvanceReadOffset (GetCount ()) : -1;
                #else // defined (TOOLCHAIN_OS_Windows)
                    ssize_t countWritten = sendto (
                        stream.GetHandle (),
                        (const char *)buffer.GetReadPtr (),
                        buffer.GetDataAvailableForReading (),
                        0,
                        &address.address,
                        address.length);
                    if (countWritten == THEKOGANS_STREAM_SOCKET_ERROR) {
                        SetError (THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                        SetCount (0);
                        return -1;
                    }
                    SetError (0);
                    SetCount (countWritten);
                    return buffer.AdvanceReadOffset ((std::size_t)countWritten);
                #endif // defined (TOOLCHAIN_OS_Windows)
                }
            };

            THEKOGANS_STREAM_IMPLEMENT_OVERLAPPED (WriteToOverlapped)
        }

        void UDPSocket::WriteTo (
                util::Buffer buffer,
                const Address &address) {
            if (!buffer.IsEmpty () && address != Address::Empty) {
            #if defined (TOOLCHAIN_OS_Windows)
                WriteToOverlapped::UniquePtr overlapped (new WriteToOverlapped (std::move (buffer), address));
                if (WSASendTo ((THEKOGANS_STREAM_SOCKET)handle,
                        &overlapped->wsaBuf,
                        1,
                        0,
                        0,
                        &overlapped->address.address,
                        overlapped->address.length,
                        overlapped.get (),
                        0) == THEKOGANS_STREAM_SOCKET_ERROR) {
                    THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_STREAM_SOCKET_ERROR_CODE;
                    if (errorCode != WSA_IO_PENDING) {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (errorCode);
                    }
                }
                overlapped.release ();
            #else // defined (TOOLCHAIN_OS_Windows)
                EnqOverlapped (
                    Overlapped::UniquePtr (new WriteToOverlapped (std::move (buffer), address)),
                    out);
            #endif // defined (TOOLCHAIN_OS_Windows)
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        void UDPSocket::WriteTo (
                const void *buffer,
                std::size_t bufferLength,
                const Address &address) {
            if (buffer != 0 && bufferLength > 0 && address != Address::Empty) {
                util::Buffer buffer_ (
                    util::NetworkEndian,
                    (const util::ui8 *)buffer,
                    (const util::ui8 *)buffer + bufferLength);
                WriteTo (std::move (buffer_), address);
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        namespace {
            struct ReadMsgOverlapped : public Overlapped {
                THEKOGANS_STREAM_DECLARE_OVERLAPPED (ReadMsgOverlapped)

            public:
                std::size_t bufferLength;
                util::Buffer buffer;
                MsgHdr msgHdr;
                Address from;
                Address to;

                ReadMsgOverlapped (std::size_t bufferLength_) :
                    bufferLength (bufferLength_),
                    buffer (util::NetworkEndian, bufferLength),
                    msgHdr (
                        buffer.GetWritePtr (),
                        buffer.GetDataAvailableForWriting (),
                        from) {}

                virtual ssize_t Prolog (Stream &stream) throw () override {
                #if defined (TOOLCHAIN_OS_Windows)
                    if (GetError () != ERROR_SUCCESS) {
                        return -1;
                    }
                    buffer.AdvanceWriteOffset (GetCount ());
                #endif // defined (TOOLCHAIN_OS_Windows)
                    if (buffer.IsEmpty ()) {
                        // If passed in bufferLength was 0, than try to grab all available data.
                        if (bufferLength == 0) {
                            u_long value = 0;
                            if (ioctlsocket ((THEKOGANS_STREAM_SOCKET)stream.GetHandle (), FIONREAD, &value) ==
                                    THEKOGANS_STREAM_SOCKET_ERROR) {
                                SetError (THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                                return -1;
                            }
                        #if !defined (TOOLCHAIN_OS_Windows)
                            if (value == 0) {
                                SetError (EWOULDBLOCK);
                                return -1;
                            }
                        #endif // !defined (TOOLCHAIN_OS_Windows)
                            buffer.Resize ((std::size_t)value);
                            msgHdr.SetBuffer (buffer.GetWritePtr (), buffer.GetDataAvailableForWriting ());
                        }
                    #if defined (TOOLCHAIN_OS_Windows)
                        DWORD countRead = 0;
                        if (WindowsFunctions::Instance ().WSARecvMsg (
                                (THEKOGANS_STREAM_SOCKET)stream.GetHandle (),
                                &msgHdr,
                                &countRead,
                                0,
                                0) == THEKOGANS_STREAM_SOCKET_ERROR) {
                            SetError (THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                            return -1;
                        }
                    #else // defined (TOOLCHAIN_OS_Windows)
                        ssize_t countRead = recvmsg (stream.GetHandle (), &msgHdr, 0);
                        if (countRead == THEKOGANS_STREAM_SOCKET_ERROR) {
                            SetError (THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                            SetCount (0);
                            return -1;
                        }
                    #endif // defined (TOOLCHAIN_OS_Windows)
                        SetError (0);
                        SetCount (countRead);
                        buffer.AdvanceWriteOffset ((std::size_t)countRead);
                    }
                    if (from.GetFamily () == AF_INET) {
                        from.length = sizeof (sockaddr_in);
                    }
                    else if (from.GetFamily () == AF_INET6) {
                        from.length = sizeof (sockaddr_in6);
                    }
                #if !defined (TOOLCHAIN_OS_Windows)
                    else if (from.GetFamily () == AF_LOCAL) {
                        from.length = sizeof (sockaddr_un);
                    }
                #endif // !defined (TOOLCHAIN_OS_Windows)
                    to = msgHdr.GetToAddress (((Socket *)&stream)->GetHostAddress ().GetPort ());
                    return buffer.GetDataAvailableForReading ();
                }

                virtual bool Epilog (Stream &stream) throw () override {
                    if (stream.IsChainRead ()) {
                        dynamic_cast<UDPSocket *> (&stream)->ReadMsg (bufferLength);
                    }
                    return true;
                }
            };

            THEKOGANS_STREAM_IMPLEMENT_OVERLAPPED (ReadMsgOverlapped)
        }

        void UDPSocket::ReadMsg (std::size_t bufferLength) {
        #if defined (TOOLCHAIN_OS_Windows)
            ReadMsgOverlapped::UniquePtr overlapped (new ReadMsgOverlapped (bufferLength));
            if (WindowsFunctions::Instance ().WSARecvMsg (
                    (THEKOGANS_STREAM_SOCKET)handle,
                    &overlapped->msgHdr,
                    0,
                    overlapped.get (),
                    0) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_STREAM_SOCKET_ERROR_CODE;
                if (errorCode != WSA_IO_PENDING) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (errorCode);
                }
            }
            overlapped.release ();
        #else // defined (TOOLCHAIN_OS_Windows)
            EnqOverlapped (
                Overlapped::UniquePtr (new ReadMsgOverlapped (bufferLength)),
                in);
        #endif // defined (TOOLCHAIN_OS_Windows)
        }

        namespace {
            struct WriteMsgOverlapped : public Overlapped {
                THEKOGANS_STREAM_DECLARE_OVERLAPPED (WriteMsgOverlapped)

            public:
                util::Buffer buffer;
                Address from;
                Address to;
                MsgHdr msgHdr;

                WriteMsgOverlapped (
                    util::Buffer buffer_,
                    const Address &from_,
                    const Address &to_) :
                    buffer (std::move (buffer_)),
                    from (from_),
                    to (to_),
                    msgHdr (
                        buffer.GetReadPtr (),
                        buffer.GetDataAvailableForReading (),
                        from,
                        to) {}

                virtual ssize_t Prolog (Stream &stream) throw () override {
                #if defined (TOOLCHAIN_OS_Windows)
                    return GetError () == ERROR_SUCCESS ? buffer.AdvanceReadOffset (GetCount ()) : -1;
                #else // defined (TOOLCHAIN_OS_Windows)
                    ssize_t countWritten = sendmsg (stream.GetHandle (), &msgHdr, 0);
                    if (countWritten == THEKOGANS_STREAM_SOCKET_ERROR) {
                        SetError (THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                        SetCount (0);
                        return -1;
                    }
                    else {
                        SetError (0);
                        SetCount (countWritten);
                        if (countWritten > 0) {
                            buffer.AdvanceReadOffset ((std::size_t)countWritten);
                            if (!buffer.IsEmpty ()) {
                                msgHdr.SetBuffer (buffer.GetReadPtr (), buffer.GetDataAvailableForReading ());
                            }
                        }
                    }
                    return countWritten;
                #endif // defined (TOOLCHAIN_OS_Windows)
                }

                virtual bool Epilog (Stream & /*stream*/) throw () override {
                    return buffer.IsEmpty ();
                }
            };

            THEKOGANS_STREAM_IMPLEMENT_OVERLAPPED (WriteMsgOverlapped)
        }

        void UDPSocket::WriteMsg (
                util::Buffer buffer,
                const Address &from,
                const Address &to) {
            if (!buffer.IsEmpty () && from != Address::Empty && to != Address::Empty) {
            #if defined (TOOLCHAIN_OS_Windows)
                WriteMsgOverlapped::UniquePtr overlapped (
                    new WriteMsgOverlapped (std::move (buffer), from, to));
                if (WindowsFunctions::Instance ().WSASendMsg (
                        (THEKOGANS_STREAM_SOCKET)handle,
                        &overlapped->msgHdr,
                        0,
                        0,
                        overlapped.get (),
                        0) == THEKOGANS_STREAM_SOCKET_ERROR) {
                    THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_STREAM_SOCKET_ERROR_CODE;
                    if (errorCode != WSA_IO_PENDING) {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                            THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                    }
                }
                overlapped.release ();
            #else // defined (TOOLCHAIN_OS_Windows)
                EnqOverlapped (
                    Overlapped::UniquePtr (
                        new WriteMsgOverlapped (std::move (buffer), from, to)),
                    out);
            #endif // defined (TOOLCHAIN_OS_Windows)
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        void UDPSocket::WriteMsg (
                const void *buffer,
                std::size_t bufferLength,
                const Address &from,
                const Address &to) {
            if (buffer != 0 && bufferLength > 0 && from != Address::Empty && to != Address::Empty) {
                util::Buffer buffer_ (
                    util::NetworkEndian,
                    (const util::ui8 *)buffer,
                    (const util::ui8 *)buffer + bufferLength);
                WriteMsg (std::move (buffer_), from, to);
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        bool UDPSocket::IsBroadcast () const {
            int arg = 0;
            socklen_t length = sizeof (arg);
            if (getsockopt ((THEKOGANS_STREAM_SOCKET)handle, SOL_SOCKET,
                    SO_BROADCAST, (char *)&arg, &length) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
            return arg == 1;
        }

        void UDPSocket::SetBroadcast (bool broadcast) {
            u_long arg = broadcast ? 1 : 0;
            if (setsockopt ((THEKOGANS_STREAM_SOCKET)handle, SOL_SOCKET,
                    SO_BROADCAST, (const char *)&arg, sizeof (arg)) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
        }

        bool UDPSocket::IsRecvPktInfo () const {
            int level;
            int optionName;
            util::ui16 family = GetFamily ();
            if (family == AF_INET) {
                level = IPPROTO_IP;
                optionName = IP_PKTINFO;
            }
            else if (family == AF_INET6) {
                level = IPPROTO_IPV6;
            #if defined (TOOLCHAIN_OS_Linux)
                optionName = IPV6_RECVPKTINFO;
            #else // defined (TOOLCHAIN_OS_Linux)
                optionName = IPV6_PKTINFO;
            #endif // defined (TOOLCHAIN_OS_Linux)
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Unknown family: %s (%u)",
                    Address::FamilyToString (family).c_str (), family);
            }
            u_long arg = 0;
            socklen_t length = sizeof (arg);
            if (getsockopt ((THEKOGANS_STREAM_SOCKET)handle, level,
                    optionName, (char *)&arg, &length) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
            return arg == 1;
        }

        void UDPSocket::SetRecvPktInfo (bool recvPktInfo) {
            int level;
            int optionName;
            util::ui16 family = GetFamily ();
            if (family == AF_INET) {
                level = IPPROTO_IP;
                optionName = IP_PKTINFO;
            }
            else if (family == AF_INET6) {
                level = IPPROTO_IPV6;
            #if defined (TOOLCHAIN_OS_Linux)
                optionName = IPV6_RECVPKTINFO;
            #else // defined (TOOLCHAIN_OS_Linux)
                optionName = IPV6_PKTINFO;
            #endif // defined (TOOLCHAIN_OS_Linux)
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Unknown family: %s (%u)",
                    Address::FamilyToString (family).c_str (), family);
            }
            u_long arg = recvPktInfo ? 1 : 0;
            if (setsockopt ((THEKOGANS_STREAM_SOCKET)handle, level,
                    optionName, (const char *)&arg, sizeof (arg)) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
        }

        #if !defined (IPV6_HDRINCL)
            #define IPV6_HDRINCL 36
        #endif // !defined (IPV6_HDRINCL)

        bool UDPSocket::IsHdrIncl () const {
            int level;
            int optionName;
            util::ui16 family = GetFamily ();
            if (family == AF_INET) {
                level = IPPROTO_IP;
                optionName = IP_HDRINCL;
            }
            else if (family == AF_INET6) {
                level = IPPROTO_IPV6;
                optionName = IPV6_HDRINCL;
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Unknown family: %s (%u)",
                    Address::FamilyToString (family).c_str (), family);
            }
            u_long arg = 0;
            socklen_t length = sizeof (arg);
            if (getsockopt ((THEKOGANS_STREAM_SOCKET)handle, level,
                    optionName, (char *)&arg, &length) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
            return arg == 1;
        }

        void UDPSocket::SetHdrIncl (bool hdrIncl) {
            int level;
            int optionName;
            util::ui16 family = GetFamily ();
            if (family == AF_INET) {
                level = IPPROTO_IP;
                optionName = IP_HDRINCL;
            }
            else if (family == AF_INET6) {
                level = IPPROTO_IPV6;
                optionName = IPV6_HDRINCL;
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Unknown family: %s (%u)",
                    Address::FamilyToString (family).c_str (), family);
            }
            u_long arg = hdrIncl ? 1 : 0;
            if (setsockopt ((THEKOGANS_STREAM_SOCKET)handle, level,
                    optionName, (const char *)&arg, sizeof (arg)) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
        }

        bool UDPSocket::IsConnected () const {
            Address address;
            return getpeername ((THEKOGANS_STREAM_SOCKET)handle,
                &address.address, &address.length) != THEKOGANS_STREAM_SOCKET_ERROR;
        }

        void UDPSocket::Connect (const Address &address) {
            if (address != Address::Empty) {
            #if defined (TOOLCHAIN_OS_Windows)
                if (WSAConnect ((THEKOGANS_STREAM_SOCKET)handle, &address.address,
                        address.length, 0, 0, 0, 0) == THEKOGANS_STREAM_SOCKET_ERROR) {
            #else // defined (TOOLCHAIN_OS_Windows)
                if (connect ((THEKOGANS_STREAM_SOCKET)handle, &address.address,
                        address.length) == THEKOGANS_STREAM_SOCKET_ERROR) {
            #endif // defined (TOOLCHAIN_OS_Windows)
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        void UDPSocket::JoinMulticastGroup (
                const Address &address,
                util::ui32 adapter) {
            if (address.GetFamily () == AF_INET) {
                ip_mreq mreq;
                mreq.imr_multiaddr = address.in.sin_addr;
                mreq.imr_interface.s_addr = htonl (adapter);
                if (setsockopt ((THEKOGANS_STREAM_SOCKET)handle, IPPROTO_IP,
                        IP_ADD_MEMBERSHIP, (const char *)&mreq, sizeof (mreq)) != 0) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
            }
            else if (address.GetFamily () == AF_INET6) {
                ipv6_mreq mreq;
                mreq.ipv6mr_multiaddr = address.in6.sin6_addr;
                mreq.ipv6mr_interface = adapter;
                if (setsockopt ((THEKOGANS_STREAM_SOCKET)handle, IPPROTO_IPV6,
                        IPV6_JOIN_GROUP, (const char *)&mreq, sizeof (mreq)) != 0) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        void UDPSocket::LeaveMulticastGroup (
                const Address &address,
                util::ui32 adapter) {
            if (address.GetFamily () == AF_INET) {
                ip_mreq mreq;
                mreq.imr_multiaddr = address.in.sin_addr;
                mreq.imr_interface.s_addr = htonl (adapter);
                if (setsockopt ((THEKOGANS_STREAM_SOCKET)handle, IPPROTO_IP,
                        IP_DROP_MEMBERSHIP, (const char *)&mreq, sizeof (mreq)) != 0) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
            }
            else if (address.GetFamily () == AF_INET6) {
                ipv6_mreq mreq;
                mreq.ipv6mr_multiaddr = address.in6.sin6_addr;
                mreq.ipv6mr_interface = adapter;
                if (setsockopt ((THEKOGANS_STREAM_SOCKET)handle, IPPROTO_IPV6,
                        IPV6_LEAVE_GROUP, (const char *)&mreq, sizeof (mreq)) != 0) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        util::ui32 UDPSocket::GetMulticastTTL () const {
            int ttl = 0;
            socklen_t length = sizeof (ttl);
            int family = GetFamily ();
            if (family == AF_INET) {
                if (getsockopt ((THEKOGANS_STREAM_SOCKET)handle, IPPROTO_IP,
                        IP_MULTICAST_TTL, (char *)&ttl, &length) != 0) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
            }
            else if (family == AF_INET6) {
                if (getsockopt ((THEKOGANS_STREAM_SOCKET)handle, IPPROTO_IPV6,
                        IPV6_MULTICAST_HOPS, (char *)&ttl, &length) != 0) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
            return ttl;
        }

        void UDPSocket::SetMulticastTTL (util::ui32 ttl) {
            int family = GetFamily ();
            if (family == AF_INET) {
                if (setsockopt ((THEKOGANS_STREAM_SOCKET)handle, IPPROTO_IP, IP_MULTICAST_TTL,
                        (const char *)&ttl, sizeof (ttl)) != 0) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
            }
            else if (family == AF_INET6) {
                if (setsockopt ((THEKOGANS_STREAM_SOCKET)handle, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
                        (const char *)&ttl, sizeof (ttl)) != 0) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        util::ui32 UDPSocket::GetMulticastSendAdapter () const {
            int adapter = 0;
            socklen_t length = sizeof (adapter);
            int family = GetFamily ();
            if (family == AF_INET) {
                if (getsockopt ((THEKOGANS_STREAM_SOCKET)handle, IPPROTO_IP,
                        IP_MULTICAST_IF, (char *)&adapter, &length) != 0) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
            }
            else if (family == AF_INET6) {
                if (getsockopt ((THEKOGANS_STREAM_SOCKET)handle, IPPROTO_IPV6,
                        IPV6_MULTICAST_IF, (char *)&adapter, &length) != 0) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
            return adapter;
        }

        void UDPSocket::SetMulticastSendAdapter (util::ui32 adapter) {
            int family = GetFamily ();
            adapter = htonl (adapter);
            if (family == AF_INET) {
                if (setsockopt ((THEKOGANS_STREAM_SOCKET)handle, IPPROTO_IP, IP_MULTICAST_IF,
                        (const char *)&adapter, sizeof (adapter)) != 0) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
            }
            else if (family == AF_INET6) {
                if (setsockopt ((THEKOGANS_STREAM_SOCKET)handle, IPPROTO_IPV6, IPV6_MULTICAST_IF,
                        (const char *)&adapter, sizeof (adapter)) != 0) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        bool UDPSocket::IsMulticastLoopback () const {
            int loopback = 0;
            socklen_t length = sizeof (loopback);
            int family = GetFamily ();
            if (family == AF_INET) {
                if (getsockopt ((THEKOGANS_STREAM_SOCKET)handle, IPPROTO_IP,
                        IP_MULTICAST_LOOP, (char *)&loopback, &length) != 0) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
            }
            else if (family == AF_INET6) {
                if (getsockopt ((THEKOGANS_STREAM_SOCKET)handle, IPPROTO_IPV6,
                        IPV6_MULTICAST_LOOP, (char *)&loopback, &length) != 0) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
            return loopback == 1;
        }

        void UDPSocket::SetMulticastLoopback (bool loopback) {
            int family = GetFamily ();
            int value = loopback ? 1 : 0;
            if (family == AF_INET) {
                if (setsockopt ((THEKOGANS_STREAM_SOCKET)handle, IPPROTO_IP, IP_MULTICAST_LOOP,
                        (const char *)&value, sizeof (value)) != 0) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
            }
            else if (family == AF_INET6) {
                if (setsockopt ((THEKOGANS_STREAM_SOCKET)handle, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
                        (const char *)&value, sizeof (value)) != 0) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        void UDPSocket::HandleOverlapped (Overlapped &overlapped) throw () {
            if (overlapped.GetType () == ReadFromOverlapped::TYPE) {
                ReadFromOverlapped &readFromOverlapped = (ReadFromOverlapped &)overlapped;
                util::Producer<UDPSocketEvents>::Produce (
                    std::bind (
                        &UDPSocketEvents::OnUDPSocketReadFrom,
                        std::placeholders::_1,
                        SharedPtr (this),
                        std::move (readFromOverlapped.buffer),
                        readFromOverlapped.address));
            }
            else if (overlapped.GetType () == WriteToOverlapped::TYPE) {
                WriteToOverlapped &writeToOverlapped = (WriteToOverlapped &)overlapped;
                util::Producer<UDPSocketEvents>::Produce (
                    std::bind (
                        &UDPSocketEvents::OnUDPSocketWriteTo,
                        std::placeholders::_1,
                        SharedPtr (this),
                        std::move (writeToOverlapped.buffer),
                        writeToOverlapped.address));
            }
            else if (overlapped.GetType () == ReadMsgOverlapped::TYPE) {
                ReadMsgOverlapped &readMsgOverlapped = (ReadMsgOverlapped &)overlapped;
                util::Producer<UDPSocketEvents>::Produce (
                    std::bind (
                        &UDPSocketEvents::OnUDPSocketReadMsg,
                        std::placeholders::_1,
                        SharedPtr (this),
                        std::move (readMsgOverlapped.buffer),
                        readMsgOverlapped.from,
                        readMsgOverlapped.to));
            }
            else if (overlapped.GetType () == WriteMsgOverlapped::TYPE) {
                WriteMsgOverlapped &writeMsgOverlapped = (WriteMsgOverlapped &)overlapped;
                util::Producer<UDPSocketEvents>::Produce (
                    std::bind (
                        &UDPSocketEvents::OnUDPSocketWriteMsg,
                        std::placeholders::_1,
                        SharedPtr (this),
                        std::move (writeMsgOverlapped.buffer),
                        writeMsgOverlapped.from,
                        writeMsgOverlapped.to));
            }
            else {
                Socket::HandleOverlapped (overlapped);
            }
        }

    } // namespace stream
} // namespace thekogans
