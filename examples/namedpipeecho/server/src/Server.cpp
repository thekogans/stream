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

#if defined (TOOLCHAIN_OS_Windows)

#include "thekogans/util/Exception.h"
#include "thekogans/util/LoggerMgr.h"
#include "thekogans/stream/NamedPipe.h"
#include "thekogans/stream/namedpipeecho/server/Server.h"

namespace thekogans {
    namespace stream {
        namespace namedpipeecho {
            namespace server {

                void Server::Start (const std::string &address_) {
                    address = address_;
                    ResetIo (true);
                }

                void Server::Stop () {
                    ResetIo (false);
                }

                void Server::OnStreamError (
                        Stream::SharedPtr stream,
                        util::Exception exception) throw () {
                    THEKOGANS_UTIL_LOG_ERROR ("%s\n", exception.Report ().c_str ());
                    RemoveConnection (stream);
                }

                void Server::OnStreamDisconnect (Stream::SharedPtr stream) throw () {
                    THEKOGANS_UTIL_LOG_INFO ("%s\n", "Connection closed.");
                    RemoveConnection (stream);
                }

                void Server::OnStreamRead (
                        Stream::SharedPtr stream,
                        util::Buffer::SharedPtr buffer) throw () {
                    if (!buffer->IsEmpty ()) {
                        stream->Write (buffer);
                    }
                }

                void Server::OnNamedPipeConnected (NamedPipe::SharedPtr namedPipe) throw () {
                    THEKOGANS_UTIL_LOG_INFO ("%s\n", "Received connection request.");
                    // Initiate an async read to listen for client requests.
                    namedPipe->Read ();
                    connections.push_back (namedPipe.Get ());
                    CreateServerNamedPipe ();
                }

                void Server::ResetIo (bool accept) {
                    util::Subscriber<stream::StreamEvents>::Unsubscribe ();
                    util::Subscriber<stream::NamedPipeEvents>::Unsubscribe ();
                    connections.clear ();
                    serverNamedPipe.Reset ();
                    if (accept) {
                        CreateServerNamedPipe ();
                    }
                }

                void Server::RemoveConnection (Stream::SharedPtr stream) {
                    std::vector<Stream::SharedPtr>::iterator it =
                        std::find (connections.begin (), connections.end (), stream);
                    if (it != connections.end ()) {
                        util::Subscriber<stream::StreamEvents>::Unsubscribe (**it);
                        connections.erase (it);
                    }
                }

                void Server::CreateServerNamedPipe () {
                    serverNamedPipe = NamedPipe::CreateServerNamedPipe (address);
                    // Setup async notifications.
                    // NOTE: We use the default EventDeliveryPolicy (ImmediateEventDeliveryPolicy).
                    // The reason for this is explained in \see{Stream}.
                    util::Subscriber<stream::StreamEvents>::Subscribe (*serverNamedPipe);
                    util::Subscriber<stream::NamedPipeEvents>::Subscribe (*serverNamedPipe);
                    // We're open for business. Start listening for client connections.
                    serverNamedPipe->Connect ();
                }

            } // namespace server
        } // namespace namedpipeecho
    } // namespace stream
} // namespace thekogans

#endif // defined (TOOLCHAIN_OS_Windows)
