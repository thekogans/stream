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

#if !defined (__thekogans_stream_udpecho_client_Options_h)
#define __thekogans_stream_udpecho_client_Options_h

#include <string>
#include "thekogans/util/Types.h"
#include "thekogans/util/Singleton.h"
#include "thekogans/util/CommandLineOptions.h"
#include "thekogans/util/LoggerMgr.h"

namespace thekogans {
    namespace stream {
        namespace udpecho {
            namespace client {

                struct Options :
                        public util::Singleton<Options>,
                        public util::CommandLineOptions {
                    bool help;
                    bool version;
                    util::ui32 logLevel;
                    util::ui16 port;
                    std::string address;
                    bool message;
                    util::ui32 seed;
                    util::ui32 iterations;

                    Options () :
                        help (false),
                        version (false),
                        logLevel (util::LoggerMgr::Info),
                        port (8854),
                        message (false),
                        seed (128),
                        iterations (16) {}

                    virtual void DoOption (
                        char option,
                        const std::string &value);
                    virtual void DoPath (const std::string & /*path*/) {}
                };

            } // namespace client
        } // namespace udpecho
    } // namespace stream
} // namespace thekogans

#endif // !defined (__thekogans_stream_udpecho_client_Options_h)
