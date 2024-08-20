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

#if !defined (__thekogans_stream_UDPSocket_h)
#define __thekogans_stream_UDPSocket_h

#include "thekogans/util/Environment.h"
#include "thekogans/util/Types.h"
#include "thekogans/stream/Config.h"
#include "thekogans/stream/Socket.h"

namespace thekogans {
    namespace stream {

        /// \brief
        /// Forward declaration of \see{UDPSocket}.
        struct UDPSocket;

        /// \struct UDPSocketEvents UDPSocket.h thekogans/stream/UDPSocket.h
        ///
        /// \brief
        /// Subscribe to UDPSocketEvents to receive \see{UDPSocket} event notifications.
        /// NOTE: See \see{StreamEvents} for an explination on why \see{util::Buffer}::SharedPtr
        /// is used in read and write events.

        struct _LIB_THEKOGANS_STREAM_DECL UDPSocketEvents {
            /// \brief
            /// dtor.
            virtual ~UDPSocketEvents () {}

            /// \brief
            /// Called when a new datagram has arrived on a UDPSocket.
            /// \param[in] udpSocket UDPSocket that received the datagram.
            /// \param[in] buffer The new datagram.
            /// \param[in] address Peer address that sent the datagram.
            virtual void OnUDPSocketReadFrom (
                util::RefCounted::SharedPtr<UDPSocket> /*udpSocket*/,
                util::Buffer::SharedPtr /*buffer*/,
                const Address & /*address*/) throw () {}
            /// \brief
            /// Called when a datagram was written to a UDPSocket.
            /// \param[in] udpSocket UDPSocket where the datagram was written.
            /// \param[in] buffer The written datagram.
            /// \param[in] address Peer address that received the datagram.
            virtual void OnUDPSocketWriteTo (
                util::RefCounted::SharedPtr<UDPSocket> /*udpSocket*/,
                util::Buffer::SharedPtr /*buffer*/,
                const Address & /*address*/) throw () {}

            /// \brief
            /// Called when a new datagram has arrived on a UDPSocket.
            /// \param[in] udpSocket UDPSocket that received the datagram.
            /// \param[in] buffer The new datagram.
            /// \param[in] from Peer address that sent the datagram.
            /// \param[in] to Local address that received the datagram.
            virtual void OnUDPSocketReadMsg (
                util::RefCounted::SharedPtr<UDPSocket> /*udpSocket*/,
                util::Buffer::SharedPtr /*buffer*/,
                const Address & /*from*/,
                const Address & /*to*/) throw () {}
            /// \brief
            /// Called when a datagram was written to a UDPSocket.
            /// \param[in] udpSocket UDPSocket where the datagram was written.
            /// \param[in] buffer The written datagram.
            /// \param[in] from Local address from which the datagram was sent.
            /// \param[in] to Peer address that will receive the datagram.
            virtual void OnUDPSocketWriteMsg (
                util::RefCounted::SharedPtr<UDPSocket> /*udpSocket*/,
                util::Buffer::SharedPtr /*buffer*/,
                const Address & /*from*/,
                const Address & /*to*/) throw () {}
        };

        /// \struct UDPSocket UDPSocket.h thekogans/stream/UDPSocket.h
        ///
        /// \brief
        /// UDPSocket is a base class for all SOCK_[DGRAM | RAW] socket derivatives.
        /// It provides all common SOCK_[DGRAM | RAW] socket apis, and let's the
        /// derivatives handle the specifics. UDPSocket implements three distinct
        /// modes of io:
        ///
        /// 1. Basic (default):
        ///    Use \see{UDPSocket::ReadFrom}/\see{UDPSocket::WriteTo}.
        /// 2. Connected (call \see{UDPSocket::Connect}):
        ///    Use \see{Stream::Read}/\see{Stream::Write}.
        /// 3. Message (call \see{UDPSocket::SetRecvPktInfo}):
        ///    Use \see{UDPSocket::ReadMsg}/\see{UDPSocket::WriteMsg}.
        ///
        /// For async UDPSockets, the type of \see{AsyncIoEventSink} callback
        /// called will depend on the io mode chosen:
        ///
        /// 1. Basic:
        ///    \see{AsyncIoEventSink::HandleUDPSocketReadFrom}, \see{AsyncIoEventSink::HandleUDPSocketWriteTo}.
        /// 2. Connected:
        ///    \see{AsyncIoEventSink::HandleStreamRead}, \see{AsyncIoEventSink::HandleStreamWrite}.
        /// 3. Message:
        ///    \see{AsyncIoEventSink::HandleUDPSocketReadMsg}, \see{AsyncIoEventSink::HandleUDPSocketWriteMsg}.

        struct _LIB_THEKOGANS_STREAM_DECL UDPSocket :
                public Socket,
                public util::Producer<UDPSocketEvents> {
            /// \brief
            /// UDPSocket is a \see{Stream}.
            THEKOGANS_STREAM_DECLARE_STREAM (UDPSocket)

            /// \brief
            /// ctor.
            /// Wrap an OS handle.
            /// \param[in] handle OS stream handle to wrap.
            explicit UDPSocket (THEKOGANS_UTIL_HANDLE handle) :
                Socket (handle) {}
            /// \brief
            /// ctor.
            /// \param[in] family Address family specification.
            /// \param[in] type Socket type specification.
            /// \param[in] protocol Socket protocol specification.
            UDPSocket (
                int family = AF_INET,
                int type = SOCK_DGRAM,
                int protocol = 0) :
                Socket (family, type, protocol) {}

            /// \brief
            /// Read a datagram and the address it was sent from.
            void ReadFrom (std::size_t bufferLength = DEFAULT_BUFFER_LENGTH);
            /// \brief
            /// Async write a datagram to the given address.
            /// NOTE: If you called \see{Connect} address is ignored.
            /// \param[in] buffer Buffer representing the datagram.
            /// \param[in] address Address the datagram is sent to.
            void WriteTo (
                util::Buffer::SharedPtr buffer,
                const Address &address);
            /// \brief
            /// Write a datagram to the given address.
            /// NOTE: If you called \see{Connect} address is ignored.
            /// \param[in] buffer Buffer representing the datagram.
            /// \param[in] bufferLength Size of buffer.
            /// \param[in] address Address the datagram is sent to.
            void WriteTo (
                const void *buffer,
                std::size_t bufferLength,
                const Address &address);

            /// \brief
            /// Use WSARecvMsg/recvmsg to read a message. This api
            /// is useful when you need to know both the sending
            /// as well as the receiving addresses. To get the
            /// receiving address, you must call SetRecvPktInfo first.
            void ReadMsg (std::size_t bufferLength = DEFAULT_BUFFER_LENGTH);
            /// \brief
            /// Async send message.
            /// \param[in] buffer Buffer that holds the message to be sent.
            /// \param[in] from The local interface address from which the message is sent.
            /// \param[in] to The address of the host that will receive the message.
            void WriteMsg (
                util::Buffer::SharedPtr buffer,
                const Address &from,
                const Address &to);
            /// \brief
            /// Use WSASendMsg/sendmsg to write a message. This api
            /// is useful when you need to know both the sending
            /// as well as the receiving addresses. To use the
            /// sending address, you must call SetRecvPktInfo first.
            /// \param[in] buffer Buffer that holds the message to be sent.
            /// \param[in] bufferLength Buffer length.
            /// \param[in] from The local interface address from which the message is sent.
            /// \param[in] to The address of the host that receive the message.
            /// \return Number of bytes sent.
            void WriteMsg (
                const void *buffer,
                std::size_t bufferLength,
                const Address &from,
                const Address &to);

            /// \brief
            /// Return true if SO_BROADCAST socket option is set.
            /// \return true = SO_BROADCAST is set, false = SO_BROADCAST is not set.
            bool IsBroadcast () const;
            /// \brief
            /// Set/Clear SO_BROADCAST socket option.
            /// \param[in] broadcast true = Set SO_BROADCAST, false = Clear SO_BROADCAST.
            void SetBroadcast (bool broadcast);

            /// \brief
            /// Return true if SetRecvPktInfo (true) was called on this socket.
            /// \return true if SetRecvPktInfo (true) was called on this socket.
            bool IsRecvPktInfo () const;
            /// \brief
            /// Set or clear the IP_PKTINFO/IPV6_PKTINFO option.
            /// VERY IMPORTANT: You must call this api before calling
            /// ReadMsg/WriteMsg or if you want to use the socket in
            /// async mode and get notifications through
            /// AsyncIoEventSink::HandleUDPSocketReadMsg/HandleUDPSocketWriteMsg.
            /// \param[in] recvPktInfo true = Set the IP_PKTINFO/IPV6_PKTINFO option,
            /// false = clear the IP_PKTINFO/IPV6_PKTINFO option.
            void SetRecvPktInfo (bool recvPktInfo);

            /// \brief
            /// Return true if SetHdrIncl (true) was called on this socket.
            /// \return true if SetHdrIncl (true) was called on this socket.
            bool IsHdrIncl () const;
            /// \brief
            /// Set or clear the IP_HDRINCL/IPV6_HDRINCL option.
            /// \param[in] hdrIncl true = Set the IP_HDRINCL/IPV6_HDRINCL option,
            /// false = clear the IP_HDRINCL/IPV6_HDRINCL option.
            void SetHdrIncl (bool hdrIncl);

            /// \brief
            /// Return true if Connect was successfully called on this socket.
            /// \return true if Connect was successfully called on this socket.
            bool IsConnected () const;
            /// \brief
            /// Sets the address that this UDPSocket will send
            /// packets to (and receive packets from).
            /// After calling this method you can use \see{Read}
            /// and \see{Write} instead of \see{ReadFrom} and
            /// \see{WriteTo}.
            /// \param[in] address Address to connect to.
            void Connect (const Address &address);

            /// \brief
            /// The following APIs provide multicast support.
            /// Address can be either AF_INET or AF_INET6 family.
            /// Socket type can be either SOCK_DGRAM or SOCK_RAW.

            /// \brief
            /// Join a multicast group.
            /// \param[in] address Multicast address group to join.
            /// See https://tools.ietf.org/html/rfc3171 and
            /// http://www.iana.org/assignments/multicast-addresses/multicast-addresses.xhtml.
            /// \param[in] adapter Adapter interface index that
            /// will receive multicast datagrams (0 = default).
            /// NOTE: Adapter indexes can be obtained by calling
            /// \see{Adapters::GetAddressesList}.
            void JoinMulticastGroup (
                const Address &address,
                util::ui32 adapter = 0);
            /// \brief
            /// Leave a multicast group.
            /// \param[in] address Multicast address group to leave.
            /// \param[in] adapter Adapter interface index that
            /// was used when joining (0 = default).
            /// NOTE: Adapter indexes can be obtained by calling
            /// \see{Adapters::GetAddressesList}.
            void LeaveMulticastGroup (
                const Address &address,
                util::ui32 adapter = 0);

            /// \brief
            /// Return the multicast hop count.
            /// \return The multicast hop count.
            util::ui32 GetMulticastTTL () const;
            /// \brief
            /// Set the multicast hop count.
            /// \param[in] ttl Multicast hop count.
            void SetMulticastTTL (util::ui32 ttl);

            /// \brief
            /// Return the multicast send adapter index.
            /// \return The multicast send adapter index.
            util::ui32 GetMulticastSendAdapter () const;
            /// \brief
            /// Set the multicast send adapter index.
            /// \param[in] adapter The multicast send adapter index.
            void SetMulticastSendAdapter (util::ui32 adapter);

            /// \brief
            /// Return true if the multicast packet is being echoed.
            /// \return true if the multicast packet is being echoed.
            bool IsMulticastLoopback () const;
            /// \brief
            /// Set to true if you want the packets you multicast to
            /// be echoed back to you.
            /// \param[in] loopback true = The packets you multicast
            /// are going to be echoed back to you.
            void SetMulticastLoopback (bool loopback);
        };

    } // namespace stream
} // namespace thekogans

#endif // !defined (__thekogans_stream_UDPSocket_h)
