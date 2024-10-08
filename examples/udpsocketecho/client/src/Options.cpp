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

#include "thekogans/util/StringUtils.h"
#include "thekogans/stream/udpecho/client/Options.h"

namespace thekogans {
    namespace stream {
        namespace udpecho {
            namespace client {

                void Options::DoOption (
                        char option,
                        const std::string &value) {
                    switch (option) {
                        case 'h':
                            help = true;
                            break;
                        case 'v':
                            version = true;
                            break;
                        case 'l':
                            logLevel =
                                util::LoggerMgr::stringTolevel (value.c_str ());
                            break;
                        case 'p':
                            port = util::stringToui16 (value.c_str ());
                            break;
                        case 'a':
                            address = value;
                            break;
                        case 'm':
                            message = true;
                            break;
                        case 'i':
                            iterations = util::stringToui32 (value.c_str ());
                            break;
                        case 'b':
                            blockSize = util::stringToui32 (value.c_str ()) * 1024;
                            break;
                    }
                }

            } // namespace client
        } // namespace udpecho
    } // namespace stream
} // namespace thekogans
