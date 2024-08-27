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

#if !defined (__thekogans_stream_tcpecho_server_Server_h)
#define __thekogans_stream_tcpecho_server_Server_h

#include <vector>
#include "thekogans/util/Types.h"
#include "thekogans/util/Singleton.h"
#include "thekogans/stream/Address.h"
#include "thekogans/stream/TCPSocket.h"

namespace thekogans {
    namespace stream {
        namespace tcpecho {
            namespace server {

                struct Server :
                        public util::RefCountedSingleton<Server>,
                        public util::Subscriber<StreamEvents>,
                        public util::Subscriber<TCPSocketEvents> {
                private:
                    TCPSocket::SharedPtr serverSocket;
                    std::vector<Stream::SharedPtr> connections;

                public:
                    void Start ();
                    void Stop ();

                private:
                    // StreamEvents
                    virtual void OnStreamError (
                        Stream::SharedPtr stream,
                        const util::Exception &exception) throw () override;
                    virtual void OnStreamDisconnect (Stream::SharedPtr stream) throw () override;
                    virtual void OnStreamRead (
                        Stream::SharedPtr stream,
                        util::Buffer::SharedPtr buffer) throw () override;
                    // TCPSocketEvents
                    virtual void OnTCPSocketAccept (
                        TCPSocket::SharedPtr /*tcpSocket*/,
                        TCPSocket::SharedPtr connection) throw () override;

                    void RemoveConnection (Stream::SharedPtr stream);
                };

            } // namespace server
        } // namespace tcpecho
    } // namespace stream
} // namespace thekogans

#endif // !defined (__thekogans_stream_tcpecho_server_Server_h)
