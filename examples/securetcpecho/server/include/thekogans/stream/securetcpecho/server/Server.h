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

#if !defined (__thekogans_stream_securetcpecho_server_Server_h)
#define __thekogans_stream_securetcpecho_server_Server_h

#include "thekogans/util/Types.h"
#include "thekogans/util/Singleton.h"
#include "thekogans/util/Thread.h"
#include "thekogans/util/JobQueue.h"
#include "thekogans/stream/Address.h"
#include "thekogans/stream/AsyncIoEventSink.h"
#include "thekogans/stream/AsyncIoEventQueue.h"
#include "thekogans/stream/ServerSecureTCPSocket.h"

namespace thekogans {
    namespace stream {
        namespace securetcpecho {
            namespace server {

                struct Server :
                        public util::Singleton<Server>,
                        public util::Thread,
                        public stream::AsyncIoEventSink {
                private:
                    bool useWriteQueue;
                    util::JobQueue jobQueue;
                    stream::AsyncIoEventQueue::UniquePtr eventQueue;
                    volatile bool done;

                public:
                    Server () :
                        useWriteQueue (false),
                        done (true) {}

                    void Start (
                        const std::string &path,
                        util::i32 priority = THEKOGANS_UTIL_NORMAL_THREAD_PRIORITY,
                        bool useWriteQueue_ = false);
                    void Stop ();

                private:
                    // util::Thread
                    virtual void Run () throw ();

                    // stream::AsyncIoEventSink
                    virtual void HandleStreamError (
                        stream::Stream &stream,
                        const util::Exception &exception) throw ();
                    virtual void HandleServerSecureTCPSocketConnection (
                        stream::ServerSecureTCPSocket &serverSecureTCPSocket,
                        stream::SecureTCPSocket::Ptr connection) throw ();
                    virtual void HandleStreamDisconnect (
                        stream::Stream &stream) throw ();
                    virtual void HandleStreamRead (
                        stream::Stream &stream,
                        util::Buffer::UniquePtr buffer) throw ();
                    virtual void HandleSecureTCPSocketHandshakeCompleted (
                        stream::SecureTCPSocket &secureTCPSocket) throw ();
                    virtual void HandleSecureTCPSocketShutdownCompleted (
                        stream::SecureTCPSocket &secureTCPSocket) throw ();
                };

            } // namespace server
        } // namespace securetcpecho
    } // namespace stream
} // namespace thekogans

#endif // !defined (__thekogans_stream_securetcpecho_server_Server_h)
