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

#include "thekogans/util/Exception.h"
#include "thekogans/util/LoggerMgr.h"
#include "thekogans/stream/UDPSocket.h"
#include "thekogans/stream/udpecho/server/Server.h"

namespace thekogans {
    namespace stream {
        namespace udpecho {
            namespace server {

                void Server::Start (
                        const Address &address_,
                        bool message_) {
                    address = address_;
                    message = message_;
                    ResetIo (true);
                }

                void Server::Stop () {
                    ResetIo (false);
                }

                void Server::OnStreamError (
                        Stream::SharedPtr stream,
                        util::Exception::SharedPtr exception) throw () {
                    THEKOGANS_UTIL_LOG_ERROR ("%s\n", exception->Report ().c_str ());
                    if (message) {
                        serverSocket->ReadMsg ();
                    }
                    else {
                        serverSocket->ReadFrom ();
                    }
                }

                void Server::OnUDPSocketReadFrom (
                        UDPSocket::SharedPtr udpSocket,
                        util::Buffer::SharedPtr buffer,
                        Address address) throw () {
                    if (!buffer->IsEmpty ()) {
                        THEKOGANS_UTIL_LOG_DEBUG (
                            "OnUDPSocketReadFrom: %s:%u (%u bytes)\n",
                            address.AddrToString ().c_str (),
                            address.GetPort (),
                            buffer->GetDataAvailableForReading ());
                        udpSocket->WriteTo (buffer, address);
                    }
                }

                void Server::OnUDPSocketReadMsg (
                        UDPSocket::SharedPtr udpSocket,
                        util::Buffer::SharedPtr buffer,
                        Address from,
                        Address to) throw () {
                    if (!buffer->IsEmpty ()) {
                        THEKOGANS_UTIL_LOG_DEBUG (
                            "OnUDPSocketReadMsg: %s:%u to: %s:%u (%u bytes)\n",
                            from.AddrToString ().c_str (),
                            from.GetPort (),
                            to.AddrToString ().c_str (),
                            to.GetPort (),
                            buffer->GetDataAvailableForReading ());
                        udpSocket->WriteMsg (buffer, from, to);
                    }
                }

                void Server::ResetIo (bool accept) {
                    // Given the nature of async io, there are no
                    // guarantees that the  serverSocket.Reset (...)
                    // call below will result in the pointers being
                    // deleted. There might be residual references
                    // on the objects just due to other threads in
                    // the code still doing some work. It is therefore
                    // imperative that we sever all communications
                    // with the old producers before connecting new
                    // ones. Stream contamination is a dangerous thing.
                    util::Subscriber<stream::StreamEvents>::Unsubscribe ();
                    util::Subscriber<stream::UDPSocketEvents>::Unsubscribe ();
                    serverSocket.Reset ();
                    if (accept) {
                        // Create a listening socket.
                        serverSocket.Reset (new stream::UDPSocket);
                        // Setup async notifications.
                        // NOTE: We use the default EventDeliveryPolicy (ImmediateEventDeliveryPolicy).
                        // The reason for this is explained in \see{Stream}.
                        util::Subscriber<stream::StreamEvents>::Subscribe (*serverSocket);
                        util::Subscriber<stream::UDPSocketEvents>::Subscribe (*serverSocket);
                        //serverSocket->SetSendBufferSize (maxPacketSize);
                        //serverSocket->SetReceiveBufferSize (maxPacketSize);
                        // Bind to the given address.
                        serverSocket->Bind (address);
                        if (message) {
                            serverSocket->SetRecvPktInfo (true);
                            serverSocket->ReadMsg ();
                        }
                        else {
                            serverSocket->ReadFrom ();
                        }
                    }
                }

            } // namespace server
        } // namespace udpecho
    } // namespace stream
} // namespace thekogans
