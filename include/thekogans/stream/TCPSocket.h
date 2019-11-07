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

#if !defined (__thekogans_stream_TCPSocket_h)
#define __thekogans_stream_TCPSocket_h

#include "thekogans/util/Constants.h"
#include "thekogans/util/SpinLock.h"
#include "thekogans/util/Exception.h"
#include "thekogans/stream/Config.h"
#include "thekogans/stream/Socket.h"

namespace thekogans {
    namespace stream {

        /// \brief
        /// Forward declaration of \see{ServerTCPSocket}.
        struct ServerTCPSocket;
        /// \brief
        /// Forward declaration of \see{ServerSecureTCPSocket}.
        struct ServerSecureTCPSocket;

        /// \struct TCPSocket TCPSocket.h thekogans/stream/TCPSocket.h
        ///
        /// \brief
        /// TCPSocket is a base class for all SOCK_STREAM socket derivatives.
        /// It provides all common SOCK_STREAM socket apis, and let's the
        /// derivatives handle the specifics.

        struct _LIB_THEKOGANS_STREAM_DECL TCPSocket : public Socket {
            /// \brief
            /// Convenient typedef for util::ThreadSafeRefCounted::Ptr<TCPSocket>.
            typedef util::ThreadSafeRefCounted::Ptr<TCPSocket> Ptr;

            /// \brief
            /// TCPSocket has a private heap to help with memory
            /// management, performance, and global heap fragmentation.
            THEKOGANS_UTIL_DECLARE_HEAP_WITH_LOCK (TCPSocket, util::SpinLock)

            /// \brief
            /// ctor.
            /// Wrap an OS handle.
            /// \param[in] handle OS stream handle to wrap.
            TCPSocket (THEKOGANS_UTIL_HANDLE handle = THEKOGANS_UTIL_INVALID_HANDLE_VALUE) :
                Socket (handle) {}
            /// \brief
            /// ctor.
            /// \param[in] family Address family specification.
            /// \param[in] type Socket type specification.
            /// \param[in] protocol Socket protocol specification.
            TCPSocket (
                int family,
                int type,
                int protocol) :
                Socket (family, type, protocol) {}

            // Stream
            /// \brief
            /// Disconnect the stream from it's peer.
            virtual void Disconnect ();

            /// \brief
            /// Read bytes from the stream.
            /// \param[out] buffer Where to place the bytes.
            /// \param[in] count Buffer length.
            /// \return Count of bytes actually placed in the buffer.
            virtual std::size_t Read (
                void *buffer,
                std::size_t count);
            /// \brief
            /// Write bytes to the stream.
            /// \param[in] buffer Bytes to write.
            /// \param[in] count Buffer length.
            /// \return Count of bytes actually written.
            virtual std::size_t Write (
                const void *buffer,
                std::size_t count);
            /// \brief
            /// Async write a buffer to the stream.
            /// \param[in] buffer Buffer to write.
            virtual void WriteBuffer (util::Buffer buffer);

            /// \brief
            /// Return true if Connect was successfully called on this socket.
            /// \return true if Connect was successfully called on this socket.
            bool IsConnected () const;
            /// \brief
            /// Connect to a host with the given address.
            /// \param[in] address Address of host to connect to.
            void Connect (const Address &address);
        #if defined (TOOLCHAIN_OS_Windows)
            /// \brief
            /// Disconnect from peer.
            /// \param[in] reuseSocket If true, the socket will be made available for Connect.
            void Disconnect (bool reuseSocket);
        #endif // defined (TOOLCHAIN_OS_Windows)

            /// \brief
            /// Return true if socket is in listening mode.
            /// \return true if socket is in listening mode.
            bool IsListening () const;
            enum {
                /// \brief
                /// Default max pending connection requests.
                DEFAULT_MAX_PENDING_CONNECTIONS = 5
            };
            /// \brief
            /// Listen for incoming connections.
            /// \param[in] maxPendingConnections Maximum number of waiting connections.
            void Listen (util::i32 maxPendingConnections = DEFAULT_MAX_PENDING_CONNECTIONS);

            /// \brief
            /// Return true if SO_KEEPALIVE option is set.
            /// \return true = SO_KEEPALIVE set, false = SO_KEEPALIVE not set.
            bool IsKeepAlive () const;
            /// \brief
            /// Set or clear the SO_KEEPALIVE option and optionally specify it's parameters.
            /// \param[in] keepAlive true = set SO_KEEPALIVE, false = clear SO_KEEPALIVE.
            /// \param[in] idleTime How long to idle before sending keepalive probes (in seconds).
            /// \param[in] interval How long to wait between each probe (in seconds).
            /// \param[in] count How many probes to send before disconnecting.
            void SetKeepAlive (
                bool keepAlive,
                util::ui32 idleTime = util::UI32_MAX,
                util::ui32 interval = util::UI32_MAX,
                util::ui32 count = util::UI32_MAX);

            /// \brief
            /// Check if the socket Nagle option is set.
            /// \return true = Nagle option is set.
            bool IsNagle () const;
            /// \brief
            /// Set the socket Nagle option.
            /// \param[in] nagle true = set, false = unset.
            void SetNagle (bool nagle);

            /// \struct Socket::Linger Socket.h thekogans/stream/Socket.h
            ///
            /// \brief
            /// Holds the information about the socket linger state.
            struct _LIB_THEKOGANS_STREAM_DECL Linger {
                /// \brief
                /// true == linger, false = don't linger.
                bool on;
                /// \brief
                /// If on == true, how long to linger.
                util::ui32 seconds;
                /// \brief
                /// ctor.
                /// \param[in] on_ true == linger, false = don't linger.
                /// \param[in] seconds_ If on == true, how long to linger.
                Linger (
                    bool on_ = false,
                    util::ui32 seconds_ = 0) :
                    on (on_),
                    seconds (seconds_) {}
            };
            /// \brief
            /// Return socket current linger state.
            /// \return Socket current linger state.
            Linger GetLinger () const;
            /// \brief
            /// Set socket new linger state.
            /// \param[in] linger Socket new linger state.
            void SetLinger (const Linger &linger);

            /// \brief
            /// Shutdown type.
            enum ShutdownType {
                /// \brief
                /// Shutdown the read end.
                ShutdownRead,
                /// \brief
                /// Shutdown the write end.
                ShutdownWrite,
                /// \brief
                /// Shutdown both the read and the write ends.
                ShutdownBoth
            };
            /// \brief
            /// Shutdown either the read or the write end of the
            /// socket without closing it.
            /// \param[in] shutdownType One of ShutdownRead,
            /// ShutdownWrite or ShutdownBoth.
            void Shutdown (ShutdownType shutdownType = ShutdownBoth);

            /// \brief
            /// Accept a pending connection.
            /// NOTE: This is a blocking function.
            /// \return Handle to new connection.
            THEKOGANS_STREAM_SOCKET Accept ();

        protected:
            // Stream
            /// \brief
            /// Used by the \see{AsyncIoEventQueue::AddStream} to
            /// allow the stream to initialize itself. When this
            /// function is called, the stream is already async,
            /// and \see{Stream::AsyncInfo} has been created. At
            /// this point the stream should do whatever stream
            /// specific initialization it needs to do.
            virtual void InitAsyncIo ();
        #if defined (TOOLCHAIN_OS_Windows)
            /// \struct TCPSocket::ConnectOverlapped TCPSocket.h thekogans/stream/TCPSocket.h
            ///
            /// \brief
            /// ConnectOverlapped is a helper class. It reduces code clutter and makes
            /// instantiating Overlapped used by \see{TCPSocket::Connect} easier.
            struct ConnectOverlapped : public AsyncInfo::Overlapped {
                /// \struct TCPSocket::ConnectOverlapped::Deleter TCPSocket.h thekogans/stream/TCPSocket.h
                ///
                /// \brief
                /// Custom deleter for ConnectOverlapped. This class is
                /// necessary to shutup msvc.
                struct Deleter {
                    /// \brief
                    /// Called by unique_ptr::~unique_ptr.
                    /// \param[in] connectOverlapped ConnectOverlapped to delete.
                    void operator () (ConnectOverlapped *connectOverlapped) {
                        if (connectOverlapped != 0) {
                            delete connectOverlapped;
                        }
                    }
                };
                /// \brief
                /// Convenient typedef for std::unique_ptr<ConnectOverlapped, Deleter>.
                typedef std::unique_ptr<ConnectOverlapped, Deleter> UniquePtr;

                /// \brief
                /// ConnectOverlapped has a private heap to help with memory
                /// management, performance, and global heap fragmentation.
                THEKOGANS_UTIL_DECLARE_HEAP_WITH_LOCK (ConnectOverlapped, util::SpinLock)

                /// \brief
                /// Address used by async TCPSocket::Connect.
                Address address;

                /// \brief
                /// ctor.
                /// \param[in] stream Stream that created this ConnectOverlapped.
                /// \param[in] address Address used by \see{TCPSocket::Connect}.
                ConnectOverlapped (
                    Stream &stream,
                    const Address &address_) :
                    Overlapped (stream, Stream::AsyncInfo::EventConnect),
                    address (address_) {}

                /// \brief
                /// ConnectOverlapped is neither copy constructable, nor assignable.
                THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (ConnectOverlapped)
            };
            /// \struct TCPSocket::AcceptOverlapped TCPSocket.h thekogans/stream/TCPSocket.h
            ///
            /// \brief
            /// AcceptOverlapped is a helper class. It reduces code clutter and makes
            /// instantiating Overlapped used by \see{TCPSocket::Accept} easier.
            struct AcceptOverlapped : public AsyncInfo::Overlapped {
                /// \struct TCPSocket::AcceptOverlapped::Deleter
                /// Stream.h thekogans/stream/Stream.h
                ///
                /// \brief
                /// Custom deleter for AcceptOverlapped. This class is
                /// necessary to shutup msvc.
                struct Deleter {
                    /// \brief
                    /// Called by unique_ptr::~unique_ptr.
                    /// \param[in] acceptOverlapped AcceptOverlapped to delete.
                    void operator () (AcceptOverlapped *acceptOverlapped) {
                        if (acceptOverlapped != 0) {
                            delete acceptOverlapped;
                        }
                    }
                };
                /// \brief
                /// Convenient typedef for std::unique_ptr<AcceptOverlapped, Deleter>.
                typedef std::unique_ptr<AcceptOverlapped, Deleter> UniquePtr;

                /// \brief
                /// AcceptOverlapped has a private heap to help with memory
                /// management, performance, and global heap fragmentation.
                THEKOGANS_UTIL_DECLARE_HEAP_WITH_LOCK (AcceptOverlapped, util::SpinLock)

                /// \brief
                /// Pending (Secure)TCPSocket used by Server(Secure)TCPSocket.
                THEKOGANS_STREAM_SOCKET connection;
                /// \brief
                /// Buffer used with AcceptEx.
                char acceptBuffer[256];
                /// \brief
                /// Count used with AcceptEx.
                DWORD bytesReceived;

                /// \brief
                /// ctor.
                /// \param[in] stream Stream that created this AcceptOverlapped.
                /// \param[in] family Address family specification.
                /// \param[in] type Socket type specification.
                /// \param[in] protocol Socket protocol specification.
                AcceptOverlapped (
                        Stream &stream,
                        int family,
                        int type,
                        int protocol) :
                        Overlapped (stream, Stream::AsyncInfo::EventConnect),
                        connection (WSASocketW (family, type, protocol, 0, 0, WSA_FLAG_OVERLAPPED)),
                        bytesReceived (0) {
                    if (connection == THEKOGANS_STREAM_INVALID_SOCKET) {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                            THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                    }
                }
                /// \brief
                /// dtor.
                /// Close the socket if no one claimed it.
                virtual ~AcceptOverlapped () {
                    if (connection != THEKOGANS_STREAM_INVALID_SOCKET) {
                        closesocket (connection);
                    }
                }

                /// \brief
                /// AcceptOverlapped is neither copy constructable, nor assignable.
                THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (AcceptOverlapped)
            };
            /// \brief
            /// Windows helper used by (Secure)TCPSocket.
            void UpdateConnectContext ();
            /// \brief
            /// Windows helper used by Server(Secure)TCPSocket.
            /// \param[in] listenningSocket Socket to use to
            /// update this sockets accept context.
            void UpdateAcceptContext (THEKOGANS_UTIL_HANDLE listenningSocket);
            /// \brief
            /// Windows helper used by Server(Secure)TCPSocket.
            /// \param[in] listenningSocket Socket to use to
            /// update the accepedSocket accept context.
            /// \param[in] acceptedSocket Socket whos accept
            /// context needs to be updated.
            static void UpdateAcceptContext (
                THEKOGANS_UTIL_HANDLE listenningSocket,
                THEKOGANS_UTIL_HANDLE acceptedSocket);
            /// \brief
            /// Return true if client socket is bound.
            /// \return true if client socket is bound.
            bool IsBound () const;
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
            /// Initiate an overlapped AcceptEx.
            void PostAsyncAccept ();
            /// \brief
            /// Used by \see{AsyncIoEventQueue::WaitForEvents} to notify the
            /// stream that an overlapped operation has completed successfully.
            /// \param[in] overlapped Overlapped that completed successfully.
            virtual void HandleOverlapped (AsyncInfo::Overlapped &overlapped) throw ();
        #else // defined (TOOLCHAIN_OS_Windows)
            /// \struct TCPSocket::ShutdownBufferInfo TCPSocket.h thekogans/stream/TCPSocket.h
            ///
            /// \brief
            /// Shutdown the socket after all async writes have completed.
            struct ShutdownBufferInfo : public AsyncInfo::BufferInfo {
                /// \brief
                /// ShutdownBufferInfo has a private heap to help with memory
                /// management, performance, and global heap fragmentation.
                THEKOGANS_UTIL_DECLARE_HEAP_WITH_LOCK (ShutdownBufferInfo, util::SpinLock)

                /// \brief
                /// \see{TCPSocket} to shutdown.
                TCPSocket &tcpSocket;
                /// \brief
                /// One of ShutdownRead, ShutdownWrite or ShutdownBoth.
                ShutdownType shutdownType;

                /// \brief
                /// ctor.
                /// \param[in] tcpSocket_ \see{TCPSocket} to shutdown.
                /// \param[in] shutdownType One of ShutdownRead,
                /// ShutdownWrite or ShutdownBoth.
                ShutdownBufferInfo (
                    TCPSocket &tcpSocket_,
                    ShutdownType shutdownType_) :
                    BufferInfo (0),
                    tcpSocket (tcpSocket_),
                    shutdownType (shutdownType_) {}

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
                /// ShutdownBufferInfo is neither copy constructable, nor assignable.
                THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (ShutdownBufferInfo)
            };
            /// \brief
            /// Used by \see{AsyncIoEventQueue::WaitForEvents} to notify the
            /// stream of pending io events.
            /// \param[in] event \see{AsyncIoEventQueue} events enum.
            virtual void HandleAsyncEvent (util::ui32 event) throw ();
        #endif // defined (TOOLCHAIN_OS_Windows)

            /// \brief
            /// \see{ServerTCPSocket} needs access to UpdateAcceptContext.
            friend struct ServerTCPSocket;
            /// \brief
            /// \see{ServerSecureTCPSocket} needs access to UpdateAcceptContext.
            friend struct ServerSecureTCPSocket;

            /// \brief
            /// Streams are neither copy constructable, nor assignable.
            THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (TCPSocket)
        };

    } // namespace stream
} // namespace thekogans

#endif // !defined (__thekogans_stream_TCPSocket_h)
