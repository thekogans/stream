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

#include <list>
#include "thekogans/util/Types.h"
#include "thekogans/util/Singleton.h"
#include "thekogans/util/Thread.h"
#include "thekogans/util/JobQueue.h"
#include "thekogans/stream/Address.h"
#include "thekogans/stream/AsyncIoEventSink.h"
#include "thekogans/stream/AsyncIoEventQueue.h"
#include "thekogans/stream/ServerTCPSocket.h"

namespace thekogans {
    namespace stream {
        namespace tcpecho {
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

                    void Start (
                        const std::list<Address> &addresses,
                        bool reuseAddress = false,
                        util::ui32 maxPendingConnections =
                            ServerTCPSocket::DEFAULT_MAX_PENDING_CONNECTIONS,
                        util::i32 priority = THEKOGANS_UTIL_NORMAL_THREAD_PRIORITY,
                        util::ui32 affinity = THEKOGANS_UTIL_MAX_THREAD_AFFINITY);
                    void Stop ();

                private:
                    // util::Thread
                    virtual void Run () throw ();

                    // util::ThreadSafeRefCounted.
                    /// \brief
                    /// We're a singleton. Our lifetime is forever.
                    virtual void Harakiri () {}

                    // AsyncIoEventSink
                    virtual void HandleStreamError (
                        Stream &stream,
                        const util::Exception &exception) throw ();
                    virtual void HandleServerTCPSocketConnection (
                        ServerTCPSocket &serverTCPSocket,
                        TCPSocket::Ptr connection) throw ();
                    virtual void HandleStreamDisconnect (
                        Stream &stream) throw ();
                    virtual void HandleStreamRead (
                        Stream &stream,
                        util::Buffer buffer) throw ();
                };

            } // namespace server
        } // namespace tcpecho
    } // namespace stream
} // namespace thekogans

#endif // !defined (__thekogans_stream_tcpecho_server_Server_h)
