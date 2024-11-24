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
#include "thekogans/stream/Overlapped.h"
#include "thekogans/stream/UDPSocket.h"

namespace thekogans {
    namespace stream {

        THEKOGANS_STREAM_IMPLEMENT_STREAM (UDPSocket)

    #if defined (TOOLCHAIN_OS_Windows)
        namespace {
            struct WindowsFunctions : public util::Singleton<WindowsFunctions> {
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

        namespace {
            struct ReadFromOverlapped : public Overlapped {
                THEKOGANS_STREAM_DECLARE_OVERLAPPED (ReadFromOverlapped)

            public:
                std::size_t bufferLength;
                util::Buffer::SharedPtr buffer;
                Address address;
            #if defined (TOOLCHAIN_OS_Windows)
                WSABUF wsaBuf;
                DWORD flags;
            #endif // defined (TOOLCHAIN_OS_Windows)

                ReadFromOverlapped (std::size_t bufferLength_) :
                        bufferLength (bufferLength_),
                        buffer (new util::NetworkBuffer (bufferLength)) {
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
                #else // defined (TOOLCHAIN_OS_Windows)
                    ssize_t countRead = recvfrom (
                        stream->GetHandle (),
                        (char *)buffer->GetWritePtr (),
                        buffer->GetDataAvailableForWriting (),
                        0,
                        &address.address,
                        &address.length);
                    if (countRead == THEKOGANS_STREAM_SOCKET_ERROR) {
                        SetError (THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                        SetCount (0);
                        return -1;
                    }
                    SetError (0);
                    SetCount (countRead);
                #endif // defined (TOOLCHAIN_OS_Windows)
                    return buffer->AdvanceWriteOffset (GetCount ());
                }

                virtual bool Epilog (Stream::SharedPtr stream) throw () override {
                    UDPSocket::SharedPtr udpSocket = stream;
                    if (udpSocket != nullptr) {
                        udpSocket->util::Producer<UDPSocketEvents>::Produce (
                            std::bind (
                                &UDPSocketEvents::OnUDPSocketReadFrom,
                                std::placeholders::_1,
                                udpSocket,
                                buffer,
                                address));
                        if (udpSocket->IsChainRead ()) {
                            udpSocket->ReadFrom (bufferLength);
                        }
                    }
                    return true;
                }
            };

            THEKOGANS_STREAM_IMPLEMENT_OVERLAPPED (ReadFromOverlapped)
        }

        void UDPSocket::ReadFrom (std::size_t bufferLength) {
            ReadFromOverlapped::SharedPtr overlapped (
                new ReadFromOverlapped (bufferLength));
        #if defined (TOOLCHAIN_OS_Windows)
            if (WSARecvFrom (
                    (THEKOGANS_STREAM_SOCKET)handle,
                    &overlapped->wsaBuf,
                    1,
                    0,
                    &overlapped->flags,
                    &overlapped->address.address,
                    &overlapped->address.length,
                    overlapped.Get (),
                    0) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_STREAM_SOCKET_ERROR_CODE;
                if (errorCode != WSA_IO_PENDING) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (errorCode);
                }
            }
            overlapped.Release ();
        #else // defined (TOOLCHAIN_OS_Windows)
            EnqOverlapped (overlapped, in);
        #endif // defined (TOOLCHAIN_OS_Windows)
        }

        namespace {
            struct WriteToOverlapped : public Overlapped {
                THEKOGANS_STREAM_DECLARE_OVERLAPPED (WriteToOverlapped)

            public:
                util::Buffer::SharedPtr buffer;
                Address address;
            #if defined (TOOLCHAIN_OS_Windows)
                WSABUF wsaBuf;
            #endif // defined (TOOLCHAIN_OS_Windows)

                WriteToOverlapped (
                        util::Buffer::SharedPtr buffer_,
                        const Address &address_) :
                        buffer (buffer_),
                        address (address_) {
                #if defined (TOOLCHAIN_OS_Windows)
                    wsaBuf.len = (ULONG)buffer->GetDataAvailableForReading ();
                    wsaBuf.buf = (char *)buffer->GetReadPtr ();
                #endif // defined (TOOLCHAIN_OS_Windows)
                }

                virtual ssize_t Prolog (Stream::SharedPtr stream) throw () override {
                #if defined (TOOLCHAIN_OS_Windows)
                    if (GetError () != ERROR_SUCCESS) {
                        return -1;
                    }
                #else // defined (TOOLCHAIN_OS_Windows)
                    ssize_t countWritten = sendto (
                        stream->GetHandle (),
                        (const char *)buffer->GetReadPtr (),
                        buffer->GetDataAvailableForReading (),
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
                #endif // defined (TOOLCHAIN_OS_Windows)
                    return buffer->AdvanceReadOffset (GetCount ());
                }

                virtual bool Epilog (Stream::SharedPtr stream) throw () override {
                    UDPSocket::SharedPtr udpSocket = stream;
                    if (udpSocket != nullptr) {
                        udpSocket->util::Producer<UDPSocketEvents>::Produce (
                            std::bind (
                                &UDPSocketEvents::OnUDPSocketWriteTo,
                                std::placeholders::_1,
                                udpSocket,
                                buffer,
                                address));
                    }
                    return true;
                }
            };

            THEKOGANS_STREAM_IMPLEMENT_OVERLAPPED (WriteToOverlapped)
        }

        void UDPSocket::WriteTo (
                util::Buffer::SharedPtr buffer,
                const Address &address) {
            if (!buffer->IsEmpty () && address != Address::Empty) {
                WriteToOverlapped::SharedPtr overlapped (
                    new WriteToOverlapped (buffer, address));
            #if defined (TOOLCHAIN_OS_Windows)
                if (WSASendTo (
                        (THEKOGANS_STREAM_SOCKET)handle,
                        &overlapped->wsaBuf,
                        1,
                        0,
                        0,
                        &overlapped->address.address,
                        overlapped->address.length,
                        overlapped.Get (),
                        0) == THEKOGANS_STREAM_SOCKET_ERROR) {
                    THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_STREAM_SOCKET_ERROR_CODE;
                    if (errorCode != WSA_IO_PENDING) {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (errorCode);
                    }
                }
                overlapped.Release ();
            #else // defined (TOOLCHAIN_OS_Windows)
                EnqOverlapped (overlapped, out);
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
            if (buffer != nullptr && bufferLength > 0 && address != Address::Empty) {
                WriteTo (
                    new util::NetworkBuffer (
                        (const util::ui8 *)buffer,
                        (const util::ui8 *)buffer + bufferLength),
                    address);
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        namespace {
            /// \brief
            /// MsgHdr is a private class used by \see{UDPSocket} to implement
            /// ReadMsg/WriteMsg. It encapsulates all the details of setting up
            /// and parsing the control buffer required by recvmsg/sendmsg and
            /// WSARecvMsg/WSASendMsg.
        #if defined (TOOLCHAIN_OS_Windows)
            struct MsgHdr : public WSAMSG {
                /// \brief
                /// Buffer struct used by WSAMSG.
                WSABUF wsaBuf;
        #else // defined (TOOLCHAIN_OS_Windows)
            struct MsgHdr : public msghdr {
                /// \brief
                /// Buffer struct used by msghdr.
                iovec ioVec;
        #endif // defined (TOOLCHAIN_OS_Windows)
                /// \brief
                /// Control buffer used by WSAMSG/msghdr.
                char controlBuffer[256];

                /// \brief
                /// ctor. Used by ReadMsg.
                /// \param[out] buffer Buffer that will receive the message.
                /// \param[in] bufferLength Buffer length.
                /// \param[out] address Local address on which the message arrived.
                MsgHdr (
                        void *buffer,
                        std::size_t bufferLength,
                        Address &address) {
                    SetBuffer (buffer, bufferLength);
                #if defined (TOOLCHAIN_OS_Windows)
                    name = &address.address;
                    namelen = address.length;
                    lpBuffers = &wsaBuf;
                    dwBufferCount = 1;
                    Control.len = 256;
                    Control.buf = controlBuffer;
                    dwFlags = 0;
                #else // defined (TOOLCHAIN_OS_Windows)
                    msg_name = &address.address;
                    msg_namelen = address.length;
                    msg_iov = &ioVec;
                    msg_iovlen = 1;
                    msg_controllen = 256;
                    msg_control = controlBuffer;
                    msg_flags = 0;
                #endif // defined (TOOLCHAIN_OS_Windows)
                }
                /// \brief
                /// ctor. Used by WriteMsg.
                /// \param[in] buffer Buffer to write.
                /// \param[in] bufferLength Length of buffer.
                /// \param[in] from Local address from which the message is sent to the peer.
                /// \param[in] to Peer address that will receive the message.
                MsgHdr (
                        const void *buffer,
                        std::size_t bufferLength,
                        const Address &from,
                        const Address &to) {
                    SetBuffer (buffer, bufferLength);
                #if defined (TOOLCHAIN_OS_Windows)
                    name = (LPSOCKADDR)&to.address;
                    namelen = to.length;
                    lpBuffers = &wsaBuf;
                    dwBufferCount = 1;
                    Control.buf = controlBuffer;
                    if (from.GetFamily () == AF_INET) {
                        Control.len = WSA_CMSG_SPACE (sizeof (IN_PKTINFO));
                        WSACMSGHDR *wsaCMsgHdr = WSA_CMSG_FIRSTHDR (this);
                        wsaCMsgHdr->cmsg_level = IPPROTO_IP;
                        wsaCMsgHdr->cmsg_type = IP_PKTINFO;
                        wsaCMsgHdr->cmsg_len = WSA_CMSG_LEN (sizeof (IN_PKTINFO));
                        IN_PKTINFO *pktInfo = (IN_PKTINFO *)WSA_CMSG_DATA (wsaCMsgHdr);
                        memset (pktInfo, 0, sizeof (IN_PKTINFO));
                        pktInfo->ipi_addr = from.GetAddr ();
                    }
                    else if (from.GetFamily () == AF_INET6) {
                        Control.len = WSA_CMSG_SPACE (sizeof (IN6_PKTINFO));
                        WSACMSGHDR *wsaCMsgHdr = WSA_CMSG_FIRSTHDR (this);
                        wsaCMsgHdr->cmsg_level = IPPROTO_IPV6;
                        wsaCMsgHdr->cmsg_type = IPV6_PKTINFO;
                        wsaCMsgHdr->cmsg_len = WSA_CMSG_LEN (sizeof (IN6_PKTINFO));
                        IN6_PKTINFO *pktInfo = (IN6_PKTINFO *)WSA_CMSG_DATA (wsaCMsgHdr);
                        memset (pktInfo, 0, sizeof (IN6_PKTINFO));
                        pktInfo->ipi6_addr = from.GetAddr6 ();
                    }
                    dwFlags = 0;
                #else // defined (TOOLCHAIN_OS_Windows)
                    msg_iov = &ioVec;
                    msg_iovlen = 1;
                    msg_name = (void *)&to.address;
                    msg_namelen = to.length;
                    msg_control = controlBuffer;
                    if (from.GetFamily () == AF_INET) {
                        msg_controllen = CMSG_SPACE (sizeof (in_pktinfo));
                        cmsghdr *cmsgHdr = CMSG_FIRSTHDR (this);
                        cmsgHdr->cmsg_level = IPPROTO_IP;
                        cmsgHdr->cmsg_type = IP_PKTINFO;
                        cmsgHdr->cmsg_len = CMSG_LEN (sizeof (in_pktinfo));
                        in_pktinfo *pktInfo = (in_pktinfo *)CMSG_DATA (cmsgHdr);
                        memset (pktInfo, 0, sizeof (in_pktinfo));
                        pktInfo->ipi_spec_dst = from.GetAddr ();
                    }
                    else if (from.GetFamily () == AF_INET6) {
                        msg_controllen = CMSG_SPACE (sizeof (in6_pktinfo));
                        cmsghdr *cmsgHdr = CMSG_FIRSTHDR (this);
                        cmsgHdr->cmsg_level = IPPROTO_IPV6;
                        cmsgHdr->cmsg_type = IPV6_PKTINFO;
                        cmsgHdr->cmsg_len = CMSG_LEN (sizeof (in6_pktinfo));
                        in6_pktinfo *pktInfo = (in6_pktinfo *)CMSG_DATA (cmsgHdr);
                        memset (pktInfo, 0, sizeof (in6_pktinfo));
                        pktInfo->ipi6_addr = from.GetAddr6 ();
                    }
                    msg_flags = 0;
                #endif // defined (TOOLCHAIN_OS_Windows)
                }

                void SetBuffer (
                        const void *buffer,
                        std::size_t bufferLength) {
                #if defined (TOOLCHAIN_OS_Windows)
                    wsaBuf.buf = (char *)buffer;
                    wsaBuf.len = (ULONG)bufferLength;
                #else // defined (TOOLCHAIN_OS_Windows)
                    ioVec.iov_base = (void *)buffer;
                    ioVec.iov_len = bufferLength;
                #endif // defined (TOOLCHAIN_OS_Windows)
                }

                /// \brief
                /// Parse the control buffer, and retrieve the message to address.
                /// \param[in] port The control buffer only holds the address.
                /// Use this port to pair that address with.
                /// \return Message to address.
                Address GetToAddress (util::ui16 port) const {
                #if defined (TOOLCHAIN_OS_Windows)
                    for (WSACMSGHDR *wsaCMsgHdr = WSA_CMSG_FIRSTHDR (this);
                            wsaCMsgHdr != nullptr;
                            wsaCMsgHdr = WSA_CMSG_NXTHDR (this, wsaCMsgHdr)) {
                        if (wsaCMsgHdr->cmsg_level == IPPROTO_IP &&
                                wsaCMsgHdr->cmsg_type == IP_PKTINFO) {
                            IN_PKTINFO *pktInfo = (IN_PKTINFO *)WSA_CMSG_DATA (wsaCMsgHdr);
                            return Address (port, pktInfo->ipi_addr);
                        }
                        if (wsaCMsgHdr->cmsg_level == IPPROTO_IPV6 &&
                                wsaCMsgHdr->cmsg_type == IPV6_PKTINFO) {
                            IN6_PKTINFO *pktInfo = (IN6_PKTINFO *)WSA_CMSG_DATA (wsaCMsgHdr);
                            return Address (port, pktInfo->ipi6_addr);
                        }
                    }
                #else // defined (TOOLCHAIN_OS_Windows)
                    for (cmsghdr *cmsghdr = CMSG_FIRSTHDR (this);
                            cmsghdr != nullptr;
                            cmsghdr = CMSG_NXTHDR ((msghdr *)this, cmsghdr)) {
                        if (cmsghdr->cmsg_level == IPPROTO_IP &&
                                cmsghdr->cmsg_type == IP_PKTINFO) {
                            in_pktinfo *pktInfo = (in_pktinfo *)CMSG_DATA (cmsghdr);
                            return Address (port, pktInfo->ipi_addr);
                        }
                        if (cmsghdr->cmsg_level == IPPROTO_IPV6 &&
                                cmsghdr->cmsg_type == IPV6_PKTINFO) {
                            in6_pktinfo *pktInfo = (in6_pktinfo *)CMSG_DATA (cmsghdr);
                            return Address (port, pktInfo->ipi6_addr);
                        }
                    }
                #endif // defined (TOOLCHAIN_OS_Windows)
                    return Address::Empty;
                }

                // FIXME: Add other data extraction methods.

                /// \brief
                /// MsgHdr is neither copy constructable, nor assignable.
                THEKOGANS_UTIL_DISALLOW_COPY_AND_ASSIGN (MsgHdr)
            };

            struct ReadMsgOverlapped : public Overlapped {
                THEKOGANS_STREAM_DECLARE_OVERLAPPED (ReadMsgOverlapped)

            public:
                std::size_t bufferLength;
                util::Buffer::SharedPtr buffer;
                Address from;
                Address to;
                MsgHdr msgHdr;

                ReadMsgOverlapped (std::size_t bufferLength_) :
                    bufferLength (bufferLength_),
                    buffer (new util::NetworkBuffer (bufferLength)),
                    msgHdr (
                        buffer->GetWritePtr (),
                        buffer->GetDataAvailableForWriting (),
                        from) {}

                virtual ssize_t Prolog (Stream::SharedPtr stream) throw () override {
                #if defined (TOOLCHAIN_OS_Windows)
                    if (GetError () != ERROR_SUCCESS) {
                        return -1;
                    }
                #else // defined (TOOLCHAIN_OS_Windows)
                    ssize_t countRead = recvmsg (stream->GetHandle (), &msgHdr, 0);
                    if (countRead == THEKOGANS_STREAM_SOCKET_ERROR) {
                        SetError (THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                        SetCount (0);
                        return -1;
                    }
                    SetError (0);
                    SetCount (countRead);
                #endif // defined (TOOLCHAIN_OS_Windows)
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
                    to = msgHdr.GetToAddress (
                        ((Socket *)stream.Get ())->GetHostAddress ().GetPort ());
                    return buffer->AdvanceWriteOffset (GetCount ());
                }

                virtual bool Epilog (Stream::SharedPtr stream) throw () override {
                    UDPSocket::SharedPtr udpSocket = stream;
                    if (udpSocket != nullptr) {
                        udpSocket->util::Producer<UDPSocketEvents>::Produce (
                            std::bind (
                                &UDPSocketEvents::OnUDPSocketReadMsg,
                                std::placeholders::_1,
                                udpSocket,
                                buffer,
                                from,
                                to));
                        if (udpSocket->IsChainRead ()) {
                            udpSocket->ReadMsg (bufferLength);
                        }
                    }
                    return true;
                }
            };

            THEKOGANS_STREAM_IMPLEMENT_OVERLAPPED (ReadMsgOverlapped)
        }

        void UDPSocket::ReadMsg (std::size_t bufferLength) {
            ReadMsgOverlapped::SharedPtr overlapped (
                new ReadMsgOverlapped (bufferLength));
        #if defined (TOOLCHAIN_OS_Windows)
            if (WindowsFunctions::Instance ()->WSARecvMsg (
                    (THEKOGANS_STREAM_SOCKET)handle,
                    &overlapped->msgHdr,
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
            EnqOverlapped (overlapped, in);
        #endif // defined (TOOLCHAIN_OS_Windows)
        }

        namespace {
            struct WriteMsgOverlapped : public Overlapped {
                THEKOGANS_STREAM_DECLARE_OVERLAPPED (WriteMsgOverlapped)

            public:
                util::Buffer::SharedPtr buffer;
                Address from;
                Address to;
                MsgHdr msgHdr;

                WriteMsgOverlapped (
                    util::Buffer::SharedPtr buffer_,
                    const Address &from_,
                    const Address &to_) :
                    buffer (buffer_),
                    from (from_),
                    to (to_),
                    msgHdr (
                        buffer->GetReadPtr (),
                        buffer->GetDataAvailableForReading (),
                        from,
                        to) {}

                virtual ssize_t Prolog (Stream::SharedPtr stream) throw () override {
                #if defined (TOOLCHAIN_OS_Windows)
                    if (GetError () != ERROR_SUCCESS) {
                        return -1;
                    }
                #else // defined (TOOLCHAIN_OS_Windows)
                    ssize_t countWritten = sendmsg (stream->GetHandle (), &msgHdr, 0);
                    if (countWritten == THEKOGANS_STREAM_SOCKET_ERROR) {
                        SetError (THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                        SetCount (0);
                        return -1;
                    }
                    SetError (0);
                    SetCount (countWritten);
                #endif // defined (TOOLCHAIN_OS_Windows)
                    return buffer->AdvanceReadOffset (GetCount ());
                }

                virtual bool Epilog (Stream::SharedPtr stream) throw () override {
                    UDPSocket::SharedPtr udpSocket = stream;
                    if (udpSocket != nullptr) {
                        udpSocket->util::Producer<UDPSocketEvents>::Produce (
                            std::bind (
                                &UDPSocketEvents::OnUDPSocketWriteMsg,
                                std::placeholders::_1,
                                udpSocket,
                                buffer,
                                from,
                                to));
                    }
                    return true;
                }
            };

            THEKOGANS_STREAM_IMPLEMENT_OVERLAPPED (WriteMsgOverlapped)
        }

        void UDPSocket::WriteMsg (
                util::Buffer::SharedPtr buffer,
                const Address &from,
                const Address &to) {
            if (!buffer->IsEmpty () && from != Address::Empty && to != Address::Empty) {
                WriteMsgOverlapped::SharedPtr overlapped (
                    new WriteMsgOverlapped (buffer, from, to));
            #if defined (TOOLCHAIN_OS_Windows)
                if (WindowsFunctions::Instance ()->WSASendMsg (
                        (THEKOGANS_STREAM_SOCKET)handle,
                        &overlapped->msgHdr,
                        0,
                        0,
                        overlapped.Get (),
                        0) == THEKOGANS_STREAM_SOCKET_ERROR) {
                    THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_STREAM_SOCKET_ERROR_CODE;
                    if (errorCode != WSA_IO_PENDING) {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                            THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                    }
                }
                overlapped.Release ();
            #else // defined (TOOLCHAIN_OS_Windows)
                EnqOverlapped (overlapped, out);
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
            if (buffer != nullptr && bufferLength > 0 &&
                    from != Address::Empty && to != Address::Empty) {
                WriteMsg (
                    new util::NetworkBuffer (
                        (const util::ui8 *)buffer,
                        (const util::ui8 *)buffer + bufferLength),
                    from,
                    to);
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

    } // namespace stream
} // namespace thekogans
