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

#if !defined (__thekogans_stream_namedpipeecho_client_Options_h)
#define __thekogans_stream_namedpipeecho_client_Options_h

#include "thekogans/util/Environment.h"

#if defined (TOOLCHAIN_OS_Windows)

#include <string>
#include "thekogans/util/Types.h"
#include "thekogans/util/Singleton.h"
#include "thekogans/util/CommandLineOptions.h"
#include "thekogans/util/LoggerMgr.h"

namespace thekogans {
    namespace stream {
        namespace namedpipeecho {
            namespace client {

                struct Options :
                        public util::Singleton<Options>,
                        public util::CommandLineOptions {
                    bool help;
                    bool version;
                    util::ui32 logLevel;
                    std::string address;
                    util::ui32 blockSize;
                    util::ui32 iterations;
                    util::ui32 timeout;

                    Options () :
                        help (false),
                        version (false),
                        logLevel (util::LoggerMgr::Info),
                        blockSize (64 * 1024),
                        iterations (16),
                        timeout (1) {}

                    virtual void DoOption (
                        char option,
                        const std::string &value);
                };

            } // namespace client
        } // namespace namedpipeecho
    } // namespace stream
} // namespace thekogans

#endif // defined (TOOLCHAIN_OS_Windows)

#endif // !defined (__thekogans_stream_namedpipeecho_client_Options_h)
