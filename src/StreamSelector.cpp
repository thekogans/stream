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

#include <errno.h>
#include <ctime>
#include <vector>
#include "thekogans/util/Types.h"
#include "thekogans/util/Exception.h"
#include "thekogans/stream/Address.h"
#include "thekogans/stream/StreamSelector.h"

namespace thekogans {
    namespace stream {

    #if defined (TOOLCHAIN_OS_Windows)
        StreamSelector::StreamSelector () :
                readPipe (Address::Loopback (0, AF_INET)),
                writePipe (readPipe.GetHostAddress ()) {
    #else // defined (TOOLCHAIN_OS_Windows)
        StreamSelector::StreamSelector () {
            Pipe::Create (readPipe, writePipe);
            if (!readPipe.IsOpen () || !writePipe.IsOpen ()) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE);
            }
    #endif // defined (TOOLCHAIN_OS_Windows)
            readPipe.SetBlocking (false);
            // NOTE: By making the write pipe async we guard against
            // a pathological case where a client calls Break enough
            // times to block forever. This combined with correct
            // error handling in Break (below) guarantees that it
            // should not be a problem.
            writePipe.SetBlocking (false);
        }

        void StreamSelector::Clear () {
            FD_ZERO (&readSet);
            AddStreamForReading (readPipe);
            FD_ZERO (&writeSet);
        }

        void StreamSelector::AddHandleForReading (THEKOGANS_UTIL_HANDLE handle) {
            if (handle != THEKOGANS_UTIL_INVALID_HANDLE_VALUE) {
                FD_SET ((THEKOGANS_STREAM_SOCKET)handle, &readSet);
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION ("%s", "Invalid handle.");
            }
        }

        void StreamSelector::AddHandleForWriting (THEKOGANS_UTIL_HANDLE handle) {
            if (handle != THEKOGANS_UTIL_INVALID_HANDLE_VALUE) {
                FD_SET ((THEKOGANS_STREAM_SOCKET)handle, &writeSet);
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION ("%s", "Invalid handle.");
            }
        }

        bool StreamSelector::Select () {
            int returnCode = select (FD_SETSIZE, &readSet, &writeSet, 0, 0);
            if (returnCode < 0) {
                if (errno == EINTR) {
                    return false;
                }
                else {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (errno);
                }
            }
            if (IsStreamReadyForReading (readPipe)) {
                std::size_t bufferSize = readPipe.GetDataAvailable ();
                if (bufferSize != 0) {
                    std::vector<util::ui8> buffer (bufferSize);
                    if (readPipe.Read (buffer.data (), bufferSize) != bufferSize) {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                            THEKOGANS_UTIL_OS_ERROR_CODE);
                    }
                }
            }
            return returnCode > 0;
        }

        bool StreamSelector::Select (const util::TimeSpec &timeSpec) {
            timeval timeVal = timeSpec.Totimeval ();
            int returnCode = select (FD_SETSIZE, &readSet, &writeSet, 0, &timeVal);
            if (returnCode < 0) {
                if (errno == EINTR) {
                    return false;
                }
                else {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (errno);
                }
            }
            if (IsStreamReadyForReading (readPipe)) {
                std::size_t bufferSize = readPipe.GetDataAvailable ();
                if (bufferSize != 0) {
                    std::vector<util::ui8> buffer (bufferSize);
                    if (readPipe.Read (buffer.data (), bufferSize) != bufferSize) {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                            THEKOGANS_UTIL_OS_ERROR_CODE);
                    }
                }
            }
            return returnCode > 0;
        }

        void StreamSelector::Break () {
            THEKOGANS_UTIL_TRY {
                writePipe.Write ("\0", 1);
            }
            THEKOGANS_UTIL_CATCH (util::Exception) {
                // Prevent the case where an application calls Break
                // repeatedly without calling WaitForEvents.
                if (exception.GetErrorCode () != EAGAIN &&
                        exception.GetErrorCode () != EWOULDBLOCK) {
                    THEKOGANS_UTIL_RETHROW_EXCEPTION (exception);
                }
            }
        }

        bool StreamSelector::IsHandleReadyForReading (THEKOGANS_UTIL_HANDLE handle) const {
            if (handle != THEKOGANS_UTIL_INVALID_HANDLE_VALUE) {
                return FD_ISSET (handle, &readSet) != 0;
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION ("%s", "Invalid handle.");
            }
        }

        bool StreamSelector::IsHandleReadyForWriting (THEKOGANS_UTIL_HANDLE handle) const {
            if (handle != THEKOGANS_UTIL_INVALID_HANDLE_VALUE) {
                return FD_ISSET (handle, &writeSet) != 0;
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION ("%s", "Invalid handle.");
            }
        }

    } // namespace stream
} // namespace thekogans
