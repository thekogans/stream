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

#if defined (TOOLCHAIN_OS_Windows)

#include <sstream>
#include "thekogans/util/XMLUtils.h"
#include "thekogans/util/Exception.h"
#include "thekogans/util/WindowsUtils.h"
#include "thekogans/stream/AsyncIoEventQueue.h"
#include "thekogans/stream/ClientNamedPipe.h"

namespace thekogans {
    namespace stream {

        THEKOGANS_STREAM_IMPLEMENT_STREAM (ClientNamedPipe)

        bool ClientNamedPipe::Wait (DWORD timeout) {
            return WaitNamedPipeW (
                util::UTF8ToUTF16 (address.GetPath ()).c_str (),
                timeout) == TRUE;
        }

        void ClientNamedPipe::Connect (LPSECURITY_ATTRIBUTES securityAttributes) {
            if (handle == THEKOGANS_UTIL_INVALID_HANDLE_VALUE) {
                handle = CreateFileW (
                    util::UTF8ToUTF16 (address.GetPath ()).c_str (),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    securityAttributes,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                    0);
                if (IsOpen ()) {
                    if (pipeType == Message) {
                        DWORD dwMode = PIPE_READMODE_MESSAGE;
                        if (!SetNamedPipeHandleState (handle, &dwMode, 0, 0)) {
                            THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                                THEKOGANS_UTIL_OS_ERROR_CODE);
                        }
                    }
                }
                else {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_UTIL_OS_ERROR_CODE);
                }
            }
        }

        void ClientNamedPipe::InitAsyncIo () {
            Overlapped::SharedPtr overlapped (new Overlapped (*this, EventConnect));
            if (!PostQueuedCompletionStatus (
                    eventQueue.GetHandle (),
                    0,
                    (ULONG_PTR)this,
                    overlapped.get ())) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE);
            }
            overlapped.Release ();
        }

        void ClientNamedPipe::HandleOverlapped (Overlapped &overlapped) throw () {
            if (overlapped.event == EventConnect) {
                THEKOGANS_UTIL_TRY {
                    PostAsyncRead ();
                    eventSink.HandleClientNamedPipeConnected (*this);
                }
                THEKOGANS_UTIL_CATCH (util::Exception) {
                    THEKOGANS_UTIL_EXCEPTION_NOTE_LOCATION (exception);
                    Produce (
                        std::bind (
                            &StreamEvents::OnStreamError,
                            std::placeholders::_1,
                            SharedPtr (this),
                            exception));
                }
            }
            else {
                NamedPipe::HandleOverlapped (overlapped);
            }
        }

    } // namespace stream
} // namespace thekogans

#endif // defined (TOOLCHAIN_OS_Windows)
