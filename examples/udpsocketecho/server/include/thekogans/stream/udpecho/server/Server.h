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

#if !defined (__thekogans_stream_udpecho_server_Server_h)
#define __thekogans_stream_udpecho_server_Server_h

#include <list>
#include "thekogans/util/Types.h"
#include "thekogans/util/Singleton.h"
#include "thekogans/stream/Address.h"
#include "thekogans/stream/UDPSocket.h"

namespace thekogans {
    namespace stream {
        namespace udpecho {
            namespace server {

                struct Server :
                        public util::Singleton<
                            Server,
                            util::SpinLock,
                            util::RefCountedInstanceCreator<Server>,
                            util::RefCountedInstanceDestroyer<Server>>,
                        public util::Subscriber<StreamEvents>,
                        public util::Subscriber<UDPSocketEvents> {
                private:
                    UDPSocket::SharedPtr serverSocket;

                public:
                    void Start ();
                    void Stop ();

                private:
                    // StreamEvents
                    virtual void OnStreamError (
                        Stream::SharedPtr stream,
                        util::Exception::SharedPtr exception) throw () override;
                    // UDPSocketEvents
                    virtual void OnUDPSocketReadFrom (
                        util::RefCounted::SharedPtr<UDPSocket> udpSocket,
                        util::Buffer::SharedPtr buffer,
                        Address address) throw () override;
                    virtual void OnUDPSocketReadMsg (
                        util::RefCounted::SharedPtr<UDPSocket> udpSocket,
                        util::Buffer::SharedPtr buffer,
                        Address from,
                        Address to) throw () override;
                };

            } // namespace server
        } // namespace udpecho
    } // namespace stream
} // namespace thekogans

#endif // !defined (__thekogans_stream_udpecho_server_Server_h)
