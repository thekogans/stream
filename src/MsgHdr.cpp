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
    #include <netinet/in.h>
#elif defined (TOOLCHAIN_OS_OSX)
    #define __APPLE_USE_RFC_3542
    #include <netinet/in.h>
#endif // defined (TOOLCHAIN_OS_Linux)
#include "thekogans/stream/Address.h"
#include "thekogans/stream/MsgHdr.h"

namespace thekogans {
    namespace stream {

        MsgHdr::MsgHdr (
                void *buffer,
                std::size_t bufferLength,
                Address &address) {
        #if defined (TOOLCHAIN_OS_Windows)
            wsaBuf.buf = (char *)buffer;
            wsaBuf.len = (ULONG)bufferLength;
            name = &address.address;
            namelen = address.length;
            lpBuffers = &wsaBuf;
            dwBufferCount = 1;
            Control.len = 256;
            Control.buf = controlBuffer;
            dwFlags = 0;
        #else // defined (TOOLCHAIN_OS_Windows)
            ioVec.iov_base = buffer;
            ioVec.iov_len = bufferLength;
            msg_name = &address.address;
            msg_namelen = address.length;
            msg_iov = &ioVec;
            msg_iovlen = 1;
            msg_controllen = 256;
            msg_control = controlBuffer;
            msg_flags = 0;
        #endif // defined (TOOLCHAIN_OS_Windows)
        }

        MsgHdr::MsgHdr (
                const void *buffer,
                std::size_t bufferLength,
                const Address &from,
                const Address &to) {
        #if defined (TOOLCHAIN_OS_Windows)
            wsaBuf.buf = (char *)buffer;
            wsaBuf.len = (ULONG)bufferLength;
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
            ioVec.iov_base = (void *)buffer;
            ioVec.iov_len = bufferLength;
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

        void MsgHdr::SetBuffer (
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

        Address MsgHdr::GetToAddress (util::ui16 port) const {
        #if defined (TOOLCHAIN_OS_Windows)
            for (WSACMSGHDR *wsaCMsgHdr = WSA_CMSG_FIRSTHDR (this);
                    wsaCMsgHdr != nullptr;
                    wsaCMsgHdr = WSA_CMSG_NXTHDR (this, wsaCMsgHdr)) {
                if (wsaCMsgHdr->cmsg_level == IPPROTO_IP && wsaCMsgHdr->cmsg_type == IP_PKTINFO) {
                    IN_PKTINFO *pktInfo = (IN_PKTINFO *)WSA_CMSG_DATA (wsaCMsgHdr);
                    return Address (port, pktInfo->ipi_addr);
                }
                if (wsaCMsgHdr->cmsg_level == IPPROTO_IPV6 && wsaCMsgHdr->cmsg_type == IPV6_PKTINFO) {
                    IN6_PKTINFO *pktInfo = (IN6_PKTINFO *)WSA_CMSG_DATA (wsaCMsgHdr);
                    return Address (port, pktInfo->ipi6_addr);
                }
            }
        #else // defined (TOOLCHAIN_OS_Windows)
            for (cmsghdr *cmsghdr = CMSG_FIRSTHDR (this);
                    cmsghdr != nullptr;
                    cmsghdr = CMSG_NXTHDR ((msghdr *)this, cmsghdr)) {
                if (cmsghdr->cmsg_level == IPPROTO_IP && cmsghdr->cmsg_type == IP_PKTINFO) {
                    in_pktinfo *pktInfo = (in_pktinfo *)CMSG_DATA (cmsghdr);
                    return Address (port, pktInfo->ipi_addr);
                }
                if (cmsghdr->cmsg_level == IPPROTO_IPV6 && cmsghdr->cmsg_type == IPV6_PKTINFO) {
                    in6_pktinfo *pktInfo = (in6_pktinfo *)CMSG_DATA (cmsghdr);
                    return Address (port, pktInfo->ipi6_addr);
                }
            }
        #endif // defined (TOOLCHAIN_OS_Windows)
            return Address::Empty;
        }

    } // namespace stream
} // namespace thekogans
