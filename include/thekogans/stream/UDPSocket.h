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

#include "thekogans/util/Types.h"
#include "thekogans/stream/Config.h"
#include "thekogans/stream/Socket.h"

namespace thekogans {
    namespace stream {

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

        struct _LIB_THEKOGANS_STREAM_DECL UDPSocket : public Socket {
            /// \brief
            /// Convenient typedef for util::RefCounted::SharedPtr<UDPSocket>.
            typedef util::RefCounted::SharedPtr<UDPSocket> SharedPtr;

            /// \brief
            /// UDPSocket has a private heap to help with memory
            /// management, performance, and global heap fragmentation.
            THEKOGANS_UTIL_DECLARE_HEAP_WITH_LOCK (UDPSocket, util::SpinLock)

            /// \brief
            /// ctor.
            /// Wrap an OS handle.
            /// \param[in] handle OS stream handle to wrap.
            UDPSocket (THEKOGANS_UTIL_HANDLE handle = THEKOGANS_UTIL_INVALID_HANDLE_VALUE) :
                Socket (handle) {}
            /// \brief
            /// ctor.
            /// \param[in] family Address family specification.
            /// \param[in] type Socket type specification.
            /// \param[in] protocol Socket protocol specification.
            UDPSocket (
                int family,
                int type,
                int protocol) :
                Socket (family, type, protocol) {}
            /// \brief
            /// ctor.
            /// \param[in] address Address to listen for datagrams on.
            /// NOTE: This is not the address used for WriteTo/ReadFrom.
            /// This address is used to setup a server listening socket.
            /// For real server sockets, use an address with a well
            /// defined port, as clients will need to know that port
            /// number to send datagrams to the server. For client
            /// side sockets, use an address with port = 0. Bind will
            /// pick an unused port, and bind the socket to it. That
            /// will be the address the server will use to communicate
            /// back to you.
            /// Alternatively, you can specify a normal address (addr and port).
            /// Bind will receive datagrams from this address only. Combined
            /// with \see{Connect}, you can then use Read/Write instead of
            /// ReadFrom/WriteTo.
            explicit UDPSocket (const Address &address);

            /// \brief
            /// Read bytes from the stream.
            /// NOTE: This method can only be called after calling \see{Connect}.
            /// \param[out] buffer Where to place the bytes.
            /// \param[in] count Buffer length.
            /// \return Count of bytes actually placed in the buffer.
            virtual std::size_t Read (
                void *buffer,
                std::size_t count);
            /// \brief
            /// Write bytes to the stream.
            /// NOTE: This method can only be called after calling \see{Connect}.
            /// \param[in] buffer Bytes to write.
            /// \param[in] count Buffer length.
            /// \return Count of bytes actually written.
            virtual std::size_t Write (
                const void *buffer,
                std::size_t count);
            /// \brief
            /// Async write a buffer to the stream.
            /// NOTE: This method can only be called after calling \see{Connect}.
            /// \param[in] buffer Buffer to write.
            virtual void WriteBuffer (util::Buffer buffer);

            /// \brief
            /// Read a datagram and the address it was sent from.
            /// \param[out] buffer Buffer to write the datagram to.
            /// \param[in] count size of buffer.
            /// \param[out] address Peer address the datagram was sent from.
            /// \return Number of bytes read.
            virtual std::size_t ReadFrom (
                void *buffer,
                std::size_t count,
                Address &address);
            /// \brief
            /// Write a datagram to the given address.
            /// NOTE: If you called \see{Connect} address is ignored.
            /// \param[in] buffer Buffer representing the datagram.
            /// \param[in] count Size of buffer.
            /// \param[in] address Address the datagram is sent to.
            /// \return Number of bytes written.
            virtual std::size_t WriteTo (
                const void *buffer,
                std::size_t count,
                const Address &address);
            /// \brief
            /// Async write a datagram to the given address.
            /// NOTE: If you called \see{Connect} address is ignored.
            /// \param[in] buffer Buffer representing the datagram.
            /// \param[in] address Address the datagram is sent to.
            virtual void WriteBufferTo (
                util::Buffer buffer,
                const Address &address);

            /// \brief
            /// Use WSARecvMsg/recvmsg to read a message. This api
            /// is useful when you need to know both the sending
            /// as well as the receiving addresses. To get the
            /// receiving address, you must call SetRecvPktInfo first.
            /// \param[out] buffer Buffer that will receive the message.
            /// \param[in] count Buffer length.
            /// \param[out] from The address of the host that sent the message.
            /// \param[out] to The local interface address that received the message.
            /// \return Number of bytes received.
            virtual std::size_t ReadMsg (
                void *buffer,
                std::size_t count,
                Address &from,
                Address &to);
            /// \brief
            /// Use WSASendMsg/sendmsg to write a message. This api
            /// is useful when you need to know both the sending
            /// as well as the receiving addresses. To use the
            /// sending address, you must call SetRecvPktInfo first.
            /// \param[in] buffer Buffer that holds the message to be sent.
            /// \param[in] count Buffer length.
            /// \param[in] from The local interface address from which the message is sent.
            /// \param[in] to The address of the host that receive the message.
            /// \return Number of bytes sent.
            virtual std::size_t WriteMsg (
                const void *buffer,
                std::size_t count,
                const Address &from,
                const Address &to);
            /// \brief
            /// Async send message.
            /// \param[in] buffer Buffer that holds the message to be sent.
            /// \param[in] from The local interface address from which the message is sent.
            /// \param[in] to The address of the host that will receive the message.
            virtual void WriteBufferMsg (
                util::Buffer buffer,
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

        protected:
            /// \brief
            /// Used by the AsyncIoEventQueue to allow the stream to
            /// initialize itself. When this function is called, the
            /// stream is already async, and \see{Stream::AsyncInfo}
            /// has been created. At this point the stream should do
            /// whatever stream specific initialization it needs to
            /// do.
            virtual void InitAsyncIo ();
        #if defined (TOOLCHAIN_OS_Windows)
            /// \struct UDPSocket::ReadFromWriteToOverlapped UDPSocket.h thekogans/stream/UDPSocket.h
            ///
            /// \brief
            /// ReadFromWriteToOverlapped is a helper class. It reduces code clutter and
            /// makes instantiating Overlapped used by \see{UDPSocket::ReadFrom} and
            /// \see{UDPSocket::WriteTo} easier.
            struct ReadFromWriteToOverlapped : public AsyncInfo::Overlapped {
                /// \brief
                /// Convenient typedef for util::RefCounted::SharedPtr<ReadFromWriteToOverlapped>.
                typedef util::RefCounted::SharedPtr<ReadFromWriteToOverlapped> SharedPtr;

                /// \brief
                /// ReadFromWriteToOverlapped has a private heap to help with memory
                /// management, performance, and global heap fragmentation.
                THEKOGANS_UTIL_DECLARE_HEAP_WITH_LOCK (ReadFromWriteToOverlapped, util::SpinLock)

                /// \brief
                /// Buffer used by UDPSocket::ReadFrom/WriteTo.
                util::Buffer buffer;
                /// \brief
                /// Address used by UDPSocket::ReadFrom/WriteTo.
                Address address;
                /// \brief
                /// WSARecvFrom/SendTo buffer.
                WSABUF wsaBuf;
                /// \brief
                /// WSARecvFrom/SendTo flags.
                DWORD flags;

                /// \brief
                /// ctor.
                /// \param[in] stream Stream that created this ReadFromWriteToOverlapped.
                /// \param[in] count Length of buffer to allocate for reading.
                /// \param[in] useGetBuffer If true, call \see{AsyncIoEventSink::GetBuffer}
                ReadFromWriteToOverlapped (
                    UDPSocket &udpSocket,
                    std::size_t count,
                    bool useGetBuffer = true);
                /// \brief
                /// ctor.
                /// \param[in] stream Stream that created this ReadFromWriteToOverlapped.
                /// \param[in] buffer_ Buffer to write.
                /// \param[in] count Lenght of buffer.
                /// \param[in] address_ Used by \see{UDPSocket::PostAsyncWriteTo}.
                /// \param[in] useGetBuffer If true, call \see{AsyncIoEventSink::GetBuffer}
                ReadFromWriteToOverlapped (
                    UDPSocket &udpSocket,
                    const void *buffer_,
                    std::size_t count,
                    const Address &address_,
                    bool useGetBuffer = true);
                /// \brief
                /// ctor.
                /// \param[in] stream Stream that created this ReadFromWriteToOverlapped.
                /// \param[in] buffer_ Buffer to write.
                /// \param[in] address_ Used by \see{UDPSocket::PostAsyncWriteTo}.
                ReadFromWriteToOverlapped (
                        UDPSocket &udpSocket,
                        util::Buffer buffer_,
                        const Address &address_) :
                        Overlapped (udpSocket, Stream::AsyncInfo::EventWriteTo),
                        buffer (std::move (buffer_)),
                        address (address_),
                        flags (0) {
                    wsaBuf.len = (ULONG)buffer.GetDataAvailableForReading ();
                    wsaBuf.buf = (char *)buffer.GetReadPtr ();
                }

                /// \brief
                /// Called by \see{AsyncIoEventQueue::WaitForEvents} to allow
                /// the ReadFromWriteToOverlapped to perform post op housekeeping.
                virtual void Epilog () throw ();

                /// \brief
                /// ReadFromWriteToOverlapped is neither copy constructable, nor assignable.
                THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (ReadFromWriteToOverlapped)
            };
            /// \struct UDPSocket::ReadMsgWriteMsgOverlapped UDPSocket.h thekogans/stream/UDPSocket.h
            ///
            /// \brief
            /// ReadMsgWriteMsgOverlapped is a helper class. It reduces code clutter and
            /// makes instantiating Overlapped used by \see{UDPSocket::PostAsyncReadMsg}
            /// easier.
            struct ReadMsgWriteMsgOverlapped : public AsyncInfo::Overlapped {
                /// \brief
                /// Convenient typedef for util::RefCounted::SharedPtr<ReadMsgWriteMsgOverlapped>.
                typedef util::RefCounted::SharedPtr<ReadMsgWriteMsgOverlapped> SharedPtr;

                /// \brief
                /// ReadMsgWriteMsgOverlapped has a private heap to help with memory
                /// management, performance, and global heap fragmentation.
                THEKOGANS_UTIL_DECLARE_HEAP_WITH_LOCK (ReadMsgWriteMsgOverlapped, util::SpinLock)

                /// \brief
                /// Buffer used by Stream::Read/Write.
                util::Buffer buffer;
                /// \brief
                /// Address from which the message was sent.
                Address from;
                /// \brief
                /// Address to which the message is sent.
                Address to;
                /// \brief
                /// Used by WSA[Recv | Send]Msg.
                MsgHdr msgHdr;

                /// \brief
                /// ctor.
                /// \param[in] stream Stream that created this ReadMsgOverlapped.
                /// \param[in] count Length of buffer to allocate for reading.
                /// \param[in] useGetBuffer If true, call \see{AsyncIoEventSink::GetBuffer}
                ReadMsgWriteMsgOverlapped (
                    UDPSocket &udpSocket,
                    std::size_t count,
                    bool useGetBuffer = true);
                /// \brief
                /// ctor.
                /// \param[in] stream Stream that created this WriteMsgOverlapped.
                /// \param[in] buffer Buffer to write.
                /// \param[in] count Lenght of buffer.
                /// \param[in] from Used by \see{UDPSocket::PostAsyncWriteMsg}.
                /// \param[in] to Used by \see{UDPSocket::PostAsyncWriteMsg}.
                /// \param[in] useGetBuffer If true, call \see{AsyncIoEventSink::GetBuffer}
                ReadMsgWriteMsgOverlapped (
                    UDPSocket &udpSocket,
                    const void *buffer_,
                    std::size_t count,
                    const Address &from_,
                    const Address &to_,
                    bool useGetBuffer = true);
                /// \brief
                /// ctor.
                /// \param[in] stream Stream that created this WriteMsgOverlapped.
                /// \param[in] buffer Buffer to write.
                /// \param[in] from Used by \see{UDPSocket::PostAsyncWriteMsg}.
                /// \param[in] to Used by \see{UDPSocket::PostAsyncWriteMsg}.
                ReadMsgWriteMsgOverlapped (
                    UDPSocket &udpSocket,
                    util::Buffer buffer_,
                    const Address &from_,
                    const Address &to_) :
                    Overlapped (udpSocket, Stream::AsyncInfo::EventWriteMsg),
                    buffer (std::move (buffer_)),
                    from (from_),
                    to (to_),
                    msgHdr (
                        buffer.GetReadPtr (),
                        buffer.GetDataAvailableForReading (),
                        from,
                        to) {}

                /// \brief
                /// Called by \see{AsyncIoEventQueue::WaitForEvents} to allow
                /// the ReadMsgWriteMsgOverlapped to perform post op housekeeping.
                virtual void Epilog () throw ();

                /// \brief
                /// ReadMsgWriteMsgOverlapped is neither copy constructable, nor assignable.
                THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (ReadMsgWriteMsgOverlapped)
            };
            /// \brief
            /// Initiate an overlapped WSARecv.
            /// \param[in] useGetBuffer If true, call \see{AsyncIoEventSink::GetBuffer}
            void PostAsyncRead (bool useGetBuffer = true);
            /// \brief
            /// Initiate an overlapped WSASend.
            /// \param[in] buffer Buffer to send.
            /// \param[in] count Length of buffer.
            /// \param[in] useGetBuffer If true, call \see{AsyncIoEventSink::GetBuffer}
            void PostAsyncWrite (
                const void *buffer,
                std::size_t count,
                bool useGetBuffer = true);
            /// \brief
            /// Initiate an overlapped WSARecvFrom.
            /// \param[in] useGetBuffer If true, call \see{AsyncIoEventSink::GetBuffer}
            void PostAsyncReadFrom (bool useGetBuffer = true);
            /// \brief
            /// Initiate an overlapped WSASendTo.
            /// \param[in] buffer Buffer to send.
            /// \param[in] count Length of buffer.
            /// \param[in] address Peer address to send the buffer to.
            /// \param[in] useGetBuffer If true, call \see{AsyncIoEventSink::GetBuffer}
            void PostAsyncWriteTo (
                const void *buffer,
                std::size_t count,
                const Address &address,
                bool useGetBuffer = true);
            /// \brief
            /// Initiate an overlapped WSARecvMsg.
            /// \param[in] useGetBuffer If true, call \see{AsyncIoEventSink::GetBuffer}
            void PostAsyncReadMsg (bool useGetBuffer = true);
            /// \brief
            /// Initiate an overlapped WSASendMsg.
            /// \param[in] buffer Buffer to send.
            /// \param[in] count Length of buffer.
            /// \param[in] address Peer address to send the buffer to.
            /// \param[in] useGetBuffer If true, call \see{AsyncIoEventSink::GetBuffer}
            void PostAsyncWriteMsg (
                const void *buffer,
                std::size_t count,
                const Address &from,
                const Address &to,
                bool useGetBuffer = true);
            /// \brief
            /// Used by AsyncIoEventQueue to notify the stream that
            /// an overlapped operation has completed successfully.
            /// \param[in] overlapped Overlapped that completed successfully.
            virtual void HandleOverlapped (AsyncInfo::Overlapped &overlapped) throw ();
        #else // defined (TOOLCHAIN_OS_Windows)
            /// \struct UDPSocket::WriteToBufferInfo UDPSocket.h thekogans/stream/UDPSocket.h
            ///
            /// \brief
            /// Uses sendto to write the buffer to the stream.
            struct WriteToBufferInfo : public AsyncInfo::BufferInfo {
                /// \brief
                /// WriteToBufferInfo has a private heap to help with memory
                /// management, performance, and global heap fragmentation.
                THEKOGANS_UTIL_DECLARE_HEAP_WITH_LOCK (WriteToBufferInfo, util::SpinLock)

                /// \brief
                /// \see{UDPSocket} to write to.
                UDPSocket &udpSocket;
                /// \brief
                /// \see{util::Buffer} to write.
                util::Buffer buffer;
                /// \brief
                /// Peer \see{Address} to write to.
                Address address;

                /// \brief
                /// ctor.
                /// \param[in] udpSocket_ \see{UDPSocket} to write to.
                /// \param[in] buffer_ \see{util::Buffer} to write.
                /// \param[in] count \see{util::Buffer} length.
                /// \param[in] address_ Peer \see{Address} to write to.
                /// \param[in] useGetBuffer If true, call \see{AsyncIoEventSink::GetBuffer}
                WriteToBufferInfo (
                    UDPSocket &udpSocket_,
                    const void *buffer_,
                    std::size_t count,
                    const Address &address_,
                    bool useGetBuffer = true);
                /// \brief
                /// ctor.
                /// \param[in] udpSocket_ \see{UDPSocket} to write to.
                /// \param[in] buffer_ \see{util::Buffer} to write.
                /// \param[in] address_ Peer \see{Address} to write to.
                WriteToBufferInfo (
                    UDPSocket &udpSocket_,
                    util::Buffer buffer_,
                    const Address &address_) :
                    BufferInfo (udpSocket_, AsyncInfo::EventWriteTo),
                    udpSocket (udpSocket_),
                    buffer (std::move (buffer_)),
                    address (address_) {}

                /// \brief
                /// Used by \see{AsyncInfo::WriteBuffers} to write
                /// the buffer to the given stream.
                /// \return Count of bytes written.
                virtual ssize_t Write ();
                /// \brief
                /// Used by \see{AsyncInfo::WriteBuffers} to complete
                /// the write operation and notify \see{AsyncIoEventSink}.
                /// \return true = \see{AsyncIoEventSink} was notified,
                /// false = \see{AsyncIoEventSink} was not notified.
                virtual bool Notify ();

                /// \brief
                /// WriteToBufferInfo is neither copy constructable, nor assignable.
                THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (WriteToBufferInfo)
            };
            /// \struct UDPSocket::WriteMsgBufferInfo UDPSocket.h thekogans/stream/UDPSocket.h
            ///
            /// \brief
            /// Uses sendmsg to write the buffer to the stream.
            struct WriteMsgBufferInfo : public AsyncInfo::BufferInfo {
                /// \brief
                /// WriteMsgBufferInfo has a private heap to help with memory
                /// management, performance, and global heap fragmentation.
                THEKOGANS_UTIL_DECLARE_HEAP_WITH_LOCK (WriteMsgBufferInfo, util::SpinLock)

                /// \brief
                /// \see{UDPSocket} to write to.
                UDPSocket &udpSocket;
                /// \brief
                /// \see{util::Buffer} to write.
                util::Buffer buffer;
                /// \brief
                /// Local \see{Address} from which the message will be written.
                Address from;
                /// \brief
                /// Peer \see{Address} that will recieve the datagram.
                Address to;

                /// \brief
                /// ctor.
                /// \param[in] udpSocket_ \see{UDPSocket} to write to.
                /// \param[in] buffer_ \see{util::Buffer} to write.
                /// \param[in] count \see{util::Buffer} length.
                /// \param[in] from_ Local \see{Address} to write from.
                /// \param[in] to_ Peer \see{Address} to write to.
                /// \param[in] useGetBuffer If true, call \see{AsyncIoEventSink::GetBuffer}
                WriteMsgBufferInfo (
                    UDPSocket &udpSocket_,
                    const void *buffer_,
                    std::size_t count,
                    const Address &from_,
                    const Address &to_,
                    bool useGetBuffer = true);
                /// \brief
                /// ctor.
                /// \param[in] udpSocket_ \see{UDPSocket} to write to.
                /// \param[in] buffer_ \see{util::Buffer} to write.
                /// \param[in] from_ Local \see{Address} to write from.
                /// \param[in] to_ Peer \see{Address} to write to.
                WriteMsgBufferInfo (
                    UDPSocket &udpSocket_,
                    util::Buffer buffer_,
                    const Address &from_,
                    const Address &to_) :
                    BufferInfo (udpSocket_, AsyncInfo::EventWriteMsg),
                    udpSocket (udpSocket_),
                    buffer (std::move (buffer_)),
                    from (from_),
                    to (to_) {}

                /// \brief
                /// Used by \see{AsyncInfo::WriteBuffers} to write
                /// the buffer to the given stream.
                /// \return Count of bytes written.
                virtual ssize_t Write ();
                /// \brief
                /// Used by \see{AsyncInfo::WriteBuffers} to complete
                /// the write operation and notify \see{AsyncIoEventSink}.
                /// \return true = \see{AsyncIoEventSink} was notified,
                /// false = \see{AsyncIoEventSink} was not notified.
                virtual bool Notify ();

                /// \brief
                /// WriteMsgBufferInfo is neither copy constructable, nor assignable.
                THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (WriteMsgBufferInfo)
            };
            /// \brief
            /// Used by AsyncIoEventQueue to notify the stream of
            /// pending io events.
            /// \param[in] events \see{AsyncIoEventQueue} events enum.
            virtual void HandleAsyncEvent (util::ui32 event) throw ();
        #endif // defined (TOOLCHAIN_OS_Windows)

            /// \brief
            /// Streams are neither copy constructable, nor assignable.
            THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (UDPSocket)
        };

    } // namespace stream
} // namespace thekogans

#endif // !defined (__thekogans_stream_UDPSocket_h)
