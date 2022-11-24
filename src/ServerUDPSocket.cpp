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

#include <algorithm>
#include <sstream>
#include "thekogans/util/Environment.h"
#include "thekogans/util/XMLUtils.h"
#include "thekogans/util/Exception.h"
#include "thekogans/stream/AsyncIoEventQueue.h"
#include "thekogans/stream/AsyncIoEventSink.h"
#include "thekogans/stream/ServerUDPSocket.h"

namespace thekogans {
    namespace stream {

        THEKOGANS_UTIL_IMPLEMENT_HEAP_WITH_LOCK (ServerUDPSocket::Connection, util::SpinLock)

        THEKOGANS_STREAM_IMPLEMENT_STREAM (ServerUDPSocket)

        const char * const ServerUDPSocket::Context::VALUE_SERVER_UDP_SOCKET = "ServerUDPSocket";
        const char * const ServerUDPSocket::Context::TAG_MAX_MESSAGE_LENGTH = "MaxMessageLength";

        void ServerUDPSocket::Context::Parse (const pugi::xml_node &node) {
            Socket::Context::Parse (node);
            for (pugi::xml_node child = node.first_child ();
                    !child.empty (); child = child.next_sibling ()) {
                if (child.type () == pugi::node_element) {
                    std::string childName = child.name ();
                    if (childName == Address::TAG_ADDRESS) {
                        address.Parse (child);
                    }
                    else if (childName == TAG_MAX_MESSAGE_LENGTH) {
                        maxMessageLength = util::stringTosize_t (child.text ().get ());
                    }
                }
            }
        }

        std::string ServerUDPSocket::Context::ToString (
                std::size_t indentationLevel,
                const char *tagName) const {
            if (tagName != 0) {
                std::ostringstream stream;
                stream <<
                    Socket::Context::ToString (indentationLevel, tagName) <<
                        address.ToString (indentationLevel + 1) <<
                        util::OpenTag (indentationLevel + 1, TAG_MAX_MESSAGE_LENGTH) <<
                            util::size_tTostring (maxMessageLength) <<
                        util::CloseTag (indentationLevel + 1, TAG_MAX_MESSAGE_LENGTH) <<
                    util::CloseTag (indentationLevel, tagName);
                return stream.str ();
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        Stream::SharedPtr ServerUDPSocket::Context::CreateStream () const {
            return Stream::SharedPtr (new ServerUDPSocket (address, maxMessageLength));
        }

        ServerUDPSocket::ServerUDPSocket (
                const Address &address,
                std::size_t maxMessageLength_) :
                UDPSocket (address.GetFamily (), SOCK_DGRAM, 0),
                maxMessageLength (maxMessageLength_) {
            SetReuseAddress (true);
        #if defined (SO_REUSEPORT) || defined (SO_REUSE_UNICASTPORT)
            SetReusePort (true);
        #endif // defined (SO_REUSEPORT) || defined (SO_REUSE_UNICASTPORT)
            Bind (address);
            SetRecvPktInfo (true);
        }

        ServerUDPSocket::Connection::SharedPtr ServerUDPSocket::Accept () {
            Connection::SharedPtr connection;
            {
                util::Buffer buffer = GetBuffer (util::NetworkEndian, maxMessageLength);
                Address from;
                Address to;
                if (buffer.AdvanceWriteOffset (
                        ReadMsg (buffer.GetWritePtr (), maxMessageLength, from, to)) > 0) {
                    connection.Reset (
                        new Connection (
                            std::move (buffer), from, to, maxMessageLength));
                }
            }
            return connection;
        }

        void ServerUDPSocket::InitAsyncIo () {
        #if defined (TOOLCHAIN_OS_Windows)
            PostAsyncReadMsg ();
        #else // defined (TOOLCHAIN_OS_Windows)
            SetBlocking (false);
            AddStreamForEvents (EventReadMsg);
        #endif // defined (TOOLCHAIN_OS_Windows)
        }

    #if defined (TOOLCHAIN_OS_Windows)
        void ServerUDPSocket::HandleOverlapped (Overlapped &overlapped) throw () {
            if (overlapped.event == EventReadMsg) {
                THEKOGANS_UTIL_TRY {
                    PostAsyncReadMsg ();
                    ReadMsgWriteMsgOverlapped &readMsgWriteMsgOverlapped =
                        (ReadMsgWriteMsgOverlapped &)overlapped;
                    if (readMsgWriteMsgOverlapped.buffer.IsEmpty ()) {
                        std::size_t bufferLength = GetDataAvailable ();
                        if (bufferLength != 0) {
                            readMsgWriteMsgOverlapped.buffer =
                                GetBuffer (*this, util::NetworkEndian, bufferLength);
                            readMsgWriteMsgOverlapped.buffer.AdvanceWriteOffset (
                                ReadMsg (
                                    readMsgWriteMsgOverlapped.buffer.GetWritePtr (),
                                    bufferLength,
                                    readMsgWriteMsgOverlapped.from,
                                    readMsgWriteMsgOverlapped.to));
                        }
                    }
                    if (!readMsgWriteMsgOverlapped.buffer.IsEmpty ()) {
                        HandleServerUDPSocketConnection (
                            *this,
                            Connection::SharedPtr (
                                new Connection (
                                    std::move (readMsgWriteMsgOverlapped.buffer),
                                    readMsgWriteMsgOverlapped.from,
                                    readMsgWriteMsgOverlapped.to,
                                    maxMessageLength)));
                    }
                }
                THEKOGANS_UTIL_CATCH (util::Exception) {
                    THEKOGANS_UTIL_EXCEPTION_NOTE_LOCATION (exception);
                    HandleStreamError (*this, exception);
                }
            }
        }
    #else // defined (TOOLCHAIN_OS_Windows)
        void ServerUDPSocket::HandleAsyncEvent (util::ui32 event) throw () {
            if (event == EventReadMsg) {
                THEKOGANS_UTIL_TRY {
                    std::size_t bufferSize = GetDataAvailable ();
                    if (bufferSize != 0) {
                        Connection::SharedPtr connection = Accept ();
                        // Connections inherit the listening socket's
                        // non-blocking state. Since we handle all
                        // async io through AsyncIoEventQueue, set the
                        // connection to blocking. If the caller
                        // decides to make the connection async, they
                        // will call AsyncIoEventQueue::AddStream
                        // explicitly.
                        connection->udpSocket->SetBlocking (true);
                        HandleServerUDPSocketConnection (
                            *this, connection);
                    }
                }
                THEKOGANS_UTIL_CATCH (util::Exception) {
                    THEKOGANS_UTIL_EXCEPTION_NOTE_LOCATION (exception);
                    HandleStreamError (*this, exception);
                }
            }
        }
    #endif // defined (TOOLCHAIN_OS_Windows)

    } // namespace stream
} // namespace thekogans
