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

#if !defined (__thekogans_stream_udpsocketecho_client_Client_h)
#define __thekogans_stream_udpsocketecho_client_Client_h

#include <string>
#include "thekogans/util/Types.h"
#include "thekogans/util/Singleton.h"
#include "thekogans/util/Subscriber.h"
#include "thekogans/util/Timer.h"
#include "thekogans/stream/Address.h"
#include "thekogans/stream/Stream.h"
#include "thekogans/stream/UDPSocket.h"

namespace thekogans {
    namespace stream {
        namespace udpecho {
            namespace client {

                struct Client :
                        public util::Singleton<
                            Client,
                            util::SpinLock,
                            util::RefCountedInstanceCreator<Client>,
                            util::RefCountedInstanceDestroyer<Client>>,
                        public util::Subscriber<util::TimerEvents>,
                        public util::Subscriber<StreamEvents>,
                        public util::Subscriber<UDPSocketEvents> {
                private:
                    Address address;
                    UDPSocket::SharedPtr clientUDPSocket;
                    util::Timer::SharedPtr timer;
                    std::size_t iteration;
                    std::size_t sentLength;
                    std::size_t receivedLength;
                    util::ui64 startTime;
                    util::ui64 endTime;

                public:
                    Client ();

                    void Start (const Address &address_);
                    void Stop ();

                private:
                    // TimerEvents
                    virtual void OnTimerAlarm (
                        util::Timer::SharedPtr /*timer*/) throw () override;

                    // StreamEvents
                    virtual void OnStreamError (
                        Stream::SharedPtr stream,
                        util::Exception::SharedPtr exception) throw () override;
                    // UDPSocketEvents
                    virtual void OnUDPSocketReadFrom (
                        UDPSocket::SharedPtr udpSocket,
                        util::Buffer::SharedPtr buffer,
                        Address address) throw () override;
                    virtual void OnUDPSocketReadMsg (
                        UDPSocket::SharedPtr udpSocket,
                        util::Buffer::SharedPtr buffer,
                        Address from,
                        Address to) throw () override;

                    void ResetIo (bool connect);
                };

            } // namespace client
        } // namespace udpecho
    } // namespace stream
} // namespace thekogans

#endif // !defined (__thekogans_stream_udpsocketecho_client_Client_h)
