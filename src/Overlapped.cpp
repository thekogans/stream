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

#include "thekogans/util/Environment.h"
#include "thekogans/stream/Stream.h"
#include "thekogans/stream/Overlapped.h"

namespace thekogans {
    namespace stream {

        bool Overlapped::Exec (Stream::SharedPtr stream) throw () {
            ssize_t result = Prolog (stream);
            if (result > 0) {
                return Epilog (stream);
            }
            else if (result == 0) {
                stream->Produce (
                    std::bind (
                        &StreamEvents::OnStreamDisconnect,
                        std::placeholders::_1,
                        stream));
                return true;
            }
            else /*result < 0*/ {
                THEKOGANS_UTIL_ERROR_CODE errorCode = GetError ();
            #if defined (TOOLCHAIN_OS_Windows)
                // Convert known errors to disconnect events.
                #define STATUS_CANCELED 0xC0000120
                #define STATUS_LOCAL_DISCONNECT 0xC000013B
                #define STATUS_REMOTE_DISCONNECT 0xC000013C
                #define STATUS_PIPE_BROKEN 0xC000014b
                #define STATUS_CONNECTION_RESET 0xC000020D
                if (errorCode == STATUS_LOCAL_DISCONNECT ||
                        errorCode == STATUS_REMOTE_DISCONNECT ||
                        errorCode == STATUS_PIPE_BROKEN ||
                        errorCode == STATUS_CONNECTION_RESET) {
                    stream->Produce (
                        std::bind (
                            &StreamEvents::OnStreamDisconnect,
                            std::placeholders::_1,
                            stream));
                    return true;
                }
            #else // defined (TOOLCHAIN_OS_Windows)
                if (errorCode == EAGAIN || errorCode == EWOULDBLOCK) {
                    return false;
                }
            #endif // defined (TOOLCHAIN_OS_Windows)
                else {
                #if defined (TOOLCHAIN_OS_Windows)
                    if (errorCode != STATUS_CANCELED) {
                #endif // defined (TOOLCHAIN_OS_Windows)
                        stream->Produce (
                            std::bind (
                                &StreamEvents::OnStreamError,
                                std::placeholders::_1,
                                stream,
                                new THEKOGANS_UTIL_ERROR_CODE_EXCEPTION (errorCode)));
                #if defined (TOOLCHAIN_OS_Windows)
                    }
                #endif // defined (TOOLCHAIN_OS_Windows)
                    return true;
                }
            }
        }

    } // namespace stream
} // namespace thekogans
