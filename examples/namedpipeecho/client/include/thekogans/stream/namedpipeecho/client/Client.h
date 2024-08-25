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

#if !defined (__thekogans_stream_namedpipeecho_client_Client_h)
#define __thekogans_stream_namedpipeecho_client_Client_h

#include "thekogans/util/Environment.h"

#if defined (TOOLCHAIN_OS_Windows)

#include <string>
#include "thekogans/util/Types.h"
#include "thekogans/util/Singleton.h"
#include "thekogans/util/Subscriber.h"
#include "thekogans/stream/Stream.h"
#include "thekogans/stream/NamedPipe.h"

namespace thekogans {
    namespace stream {
        namespace namedpipeecho {
            namespace client {

                struct Client :
                        public util::Singleton<
                            Client,
                            util::SpinLock,
                            util::RefCountedInstanceCreator<Client>,
                            util::RefCountedInstanceDestroyer<Client>>,
                        public util::Subscriber<StreamEvents> {
                private:
                    NamedPipe::SharedPtr clientNamedPipe;
                    std::size_t iteration;
                    util::ui64 startTime;
                    util::ui64 totalTime;
                    std::size_t receivedLength;

                public:
                    Client () :
                        iteration (0),
                        startTime (0),
                        totalTime (0),
                        receivedLength (0) {}

                    void Start ();
                    void Stop ();
                    void PerformTest ();

                private:
                    // StreamEvents
                    virtual void OnStreamError (
                        Stream::SharedPtr stream,
                        const util::Exception &exception) throw () override;
                    virtual void OnStreamDisconnect (
                        Stream::SharedPtr stream) throw () override;
                    virtual void OnStreamRead (
                        Stream::SharedPtr stream,
                        util::Buffer::SharedPtr buffer) throw () override;
                };

            } // namespace client
        } // namespace namedpipeecho
    } // namespace stream
} // namespace thekogans

#endif // defined (TOOLCHAIN_OS_Windows)

#endif // !defined (__thekogans_stream_namedpipeecho_client_Client_h)
