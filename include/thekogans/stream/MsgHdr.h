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

#if !defined (__thekogans_stream_MsgHdr_h)
#define __thekogans_stream_MsgHdr_h

#if defined (TOOLCHAIN_OS_Windows)
    #if !defined (_WINDOWS_)
        #if !defined (WIN32_LEAN_AND_MEAN)
            #define WIN32_LEAN_AND_MEAN
        #endif // !defined (WIN32_LEAN_AND_MEAN)
        #if !defined (NOMINMAX)
            #define NOMINMAX
        #endif // !defined (NOMINMAX)
    #endif // !defined (_WINDOWS_)
    #include <winsock2.h>
#else // defined (TOOLCHAIN_OS_Windows)
    #include <sys/socket.h>
    #include <sys/uio.h>
#endif // defined (TOOLCHAIN_OS_Windows)
#include "thekogans/util/Types.h"
#include "thekogans/stream/Config.h"
#include "thekogans/stream/Address.h"

namespace thekogans {
    namespace stream {

        /// \struct MsgHdr Address.h thekogans/stream/MsgHdr.h
        ///
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
            /// \param[in] count Buffer length.
            /// \param[out] address Local address on which the message arrived.
            MsgHdr (
                void *buffer,
                util::ui32 count,
                Address &address);
            /// \brief
            /// ctor. Used by WriteMsg.
            /// \param[in] buffer Buffer to write.
            /// \param[in] count Length of buffer.
            /// \param[in] from Local address from which the message is sent to the peer.
            /// \param[in] to Peer address that will receive the message.
            MsgHdr (
                const void *buffer,
                util::ui32 count,
                const Address &from,
                const Address &to);

            /// \brief
            /// Parse the control buffer, and retrieve the message to address.
            /// \param[in] port The control buffer only holds the address.
            /// Use this port to pair that address with.
            /// \return Message to address.
            Address GetToAddress (util::ui16 port) const;

            // FIXME: Add other data extraction methods.

            /// \brief
            /// MsgHdr is neither copy constructable, nor assignable.
            THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (MsgHdr)
        };

    } // namespace stream
} // namespace thekogans

#endif // !defined (__thekogans_stream_MsgHdr_h)
