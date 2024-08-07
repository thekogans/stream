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

    #if defined (TOOLCHAIN_OS_Windows)
        void Overlapped::Exec (Stream::SharedPtr stream) throw () {
            ssize_t result = Prolog (stream);
            if (result > 0) {
                // A slight departure in logic from the ExecOverlapped below (POSIX).
                // Under normal circumstances, Epilog will (should) always return
                // true on Windows as there are no second chances for overlapped.
                // But even if one decides to return false we still want to call
                // HandleOverlapped because, again, on Windows the callback is per
                // overlapped and therefore that overlapped is handled as far as
                // the os is concerned.
                Epilog (stream);
            }
            else if (result == 0) {
                stream->Produce (
                    std::bind (
                        &StreamEvents::OnStreamDisconnect,
                        std::placeholders::_1,
                        stream));
            }
            else /*result < 0*/ {
                THEKOGANS_UTIL_ERROR_CODE errorCode = GetError ();
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
                }
                else if (errorCode != STATUS_CANCELED) {
                    stream->Produce (
                        std::bind (
                            &StreamEvents::OnStreamError,
                            std::placeholders::_1,
                            stream,
                            new THEKOGANS_UTIL_ERROR_CODE_EXCEPTION (errorCode)));
                }
            }
        }
    #else // defined (TOOLCHAIN_OS_Windows)
        bool Overlapped::Exec (Stream::SharedPtr stream) throw () {
            ssize_t result = Prolog (stream);
            if (result > 0) {
                if (Epilog (stream)) {
                    return true;
                }
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
                if (errorCode == EAGAIN || errorCode == EWOULDBLOCK) {
                    return false;
                }
                else {
                    stream->Produce (
                        std::bind (
                            &StreamEvents::OnStreamError,
                            std::placeholders::_1,
                            stream,
                            new THEKOGANS_UTIL_ERROR_CODE_EXCEPTION (errorCode)));
                    return true;
                }
            }
        }
    #endif // defined (TOOLCHAIN_OS_Windows)

    } // namespace stream
} // namespace thekogans
