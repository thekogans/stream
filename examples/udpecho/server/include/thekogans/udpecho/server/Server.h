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
#include "thekogans/util/Thread.h"
#include "thekogans/util/JobQueue.h"
#include "thekogans/stream/Address.h"
#include "thekogans/stream/AsyncIoEventSink.h"
#include "thekogans/stream/AsyncIoEventQueue.h"

namespace thekogans {
    namespace stream {
        namespace udpecho {
            namespace server {

                struct Server :
                        public util::Singleton<Server>,
                        public util::Thread,
                        public AsyncIoEventSink {
                private:
                    util::JobQueue jobQueue;
                    AsyncIoEventQueue::UniquePtr eventQueue;
                    volatile bool done;

                public:
                    Server () :
                        done (true) {}

                    enum {
                        DEFAULT_MAX_PACKET_SIZE = 64 * 1024
                    };

                    void Start (
                        const std::list<Address> &addresses,
                        bool message = false,
                        util::ui32 maxPacketSize = DEFAULT_MAX_PACKET_SIZE,
                        util::i32 priority = THEKOGANS_UTIL_NORMAL_THREAD_PRIORITY);
                    void Stop ();

                private:
                    // util::Thread
                    virtual void Run ();

                    // AsyncIoEventSink
                    virtual void HandleStreamError (
                        Stream &stream,
                        const util::Exception &exception) throw ();
                    virtual void HandleUDPSocketReadFrom (
                        UDPSocket &udpSocket,
                        util::Buffer::UniquePtr buffer,
                        const Address &address) throw ();
                    virtual void HandleUDPSocketWriteTo (
                        UDPSocket &udpSocket,
                        util::Buffer::UniquePtr buffer,
                        const Address &address) throw ();
                    virtual void HandleUDPSocketReadMsg (
                        UDPSocket &udpSocket,
                        util::Buffer::UniquePtr buffer,
                        const Address &from,
                        const Address &to) throw ();
                    virtual void HandleUDPSocketWriteMsg (
                        UDPSocket &udpSocket,
                        util::Buffer::UniquePtr buffer,
                        const Address &from,
                        const Address &to) throw ();
                };

            } // namespace server
        } // namespace udpecho
    } // namespace stream
} // namespace thekogans

#endif // !defined (__thekogans_stream_udpecho_server_Server_h)
