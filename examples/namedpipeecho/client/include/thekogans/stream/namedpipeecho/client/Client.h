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

#if defined (TOOLCHAIN_OS_Windows)

#include <string>
#include "thekogans/util/Types.h"
#include "thekogans/util/Singleton.h"
#include "thekogans/util/Subscriber.h"
#include "thekogans/util/Timer.h"
#include "thekogans/stream/Stream.h"
#include "thekogans/stream/NamedPipe.h"
#include "thekogans/stream/namedpipeecho/client/Options.h"

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
                        public util::Subscriber<util::TimerEvents>,
                        public util::Subscriber<StreamEvents> {
                private:
                    std::string address;
                    NamedPipe::SharedPtr clientNamedPipe;
                    util::Timer::SharedPtr timer;
                    std::size_t iteration;
                    std::size_t sentLength;
                    std::size_t receivedLength;
                    util::ui64 startTime;
                    util::ui64 endTime;

                public:
                    Client () :
                            timer (util::Timer::Create ("Client")),
                            iteration (1),
                            sentLength (Options::Instance ()->seed),
                            receivedLength (0),
                            startTime (0),
                            endTime (0) {
                        util::Subscriber<util::TimerEvents>::Subscribe (*timer);
                    }

                    void Start (const std::string &address_);
                    void Stop ();

                private:
                    // TimerEvents
                    virtual void OnTimerAlarm (util::Timer::SharedPtr /*timer*/) throw () override;

                    // StreamEvents
                    virtual void OnStreamError (
                        Stream::SharedPtr stream,
                        util::Exception::SharedPtr exception) throw () override;
                    virtual void OnStreamDisconnect (
                        Stream::SharedPtr stream) throw () override;
                    virtual void OnStreamRead (
                        Stream::SharedPtr stream,
                        util::Buffer::SharedPtr buffer) throw () override;

                    void ResetIo (bool connect);
                };

            } // namespace client
        } // namespace namedpipeecho
    } // namespace stream
} // namespace thekogans

#endif // defined (TOOLCHAIN_OS_Windows)

#endif // !defined (__thekogans_stream_namedpipeecho_client_Client_h)
