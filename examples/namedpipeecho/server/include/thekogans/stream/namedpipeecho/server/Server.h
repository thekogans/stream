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

#if !defined (__thekogans_stream_namedpipeecho_server_Server_h)
#define __thekogans_stream_namedpipeecho_server_Server_h

#if defined (TOOLCHAIN_OS_Windows)

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
        namespace namedpipeecho {
            namespace server {

                struct Server :
                        public util::Singleton<Server>,
                        public util::Thread,
                        public stream::AsyncIoEventSink {
                private:
                    util::JobQueue jobQueue;
                    stream::AsyncIoEventQueue::SharedPtr eventQueue;
                    volatile bool done;

                public:
                    Server () :
                        done (true) {}

                    void Start (
                        const std::list<stream::Address> &addresses,
                        util::i32 priority = THEKOGANS_UTIL_NORMAL_THREAD_PRIORITY);
                    void Stop ();

                private:
                    // util::Thread
                    virtual void Run () throw ();

                    // util::ThreadSafeRefCounted.
                    /// \brief
                    /// We're a singleton. Our lifetime is forever.
                    virtual void Harakiri () {}

                    // stream::AsyncIoEventSink
                    virtual void HandleStreamError (
                        stream::Stream &stream,
                        const util::Exception &exception) throw ();
                    virtual void HandleServerNamedPipeConnection (
                        stream::ServerNamedPipe &serverNamedPipe) throw ();
                    virtual void HandleStreamDisconnect (
                        stream::Stream &stream) throw ();
                    virtual void HandleStreamRead (
                        stream::Stream &stream,
                        util::Buffer buffer) throw ();
                };

            } // namespace server
        } // namespace namedpipeecho
    } // namespace stream
} // namespace thekogans

#endif // defined (TOOLCHAIN_OS_Windows)

#endif // !defined (__thekogans_stream_namedpipeecho_server_Server_h)
