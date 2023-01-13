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

#include <cassert>
#include "thekogans/util/Exception.h"
#include "thekogans/stream/ClinetNamedPipe.h"

namespace thekogans {
    namespace stream {

        namespace {
            inline THEKOGANS_UTIL_HANDLE CreateFile (
                    LPCWSTR name,
                    DWORD desiredAccess,
                    DWORD shareMode,
                    LPSECURITY_ATTRIBUTES securityAttributes,
                    DWORD creationDisposition,
                    DWORD flagsAndAttributes,
                    HANDLE templateFile) {
                if (name != 0) {
                    THEKOGANS_UTIL_HANDLE handle = CreateFileW (
                        name,
                        desiredAccess,
                        shareMode,
                        securityAttributes,
                        creationDisposition,
                        flagsAndAttributes | FILE_FLAG_OVERLAPPED,
                        templateFile);
                    if (handle == THEKOGANS_UTIL_INVALID_HANDLE_VALUE) {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                            THEKOGANS_UTIL_OS_ERROR_CODE);
                    }
                    return handle;
                }
                else {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
                }
            }
        }

        void ClientNamedPipe::ClientNamedPipe (
            LPCWSTR name,
            DWORD desiredAccess,
            DWORD shareMode,
            LPSECURITY_ATTRIBUTES securityAttributes,
            DWORD creationDisposition,
            DWORD flagsAndAttributes,
            HANDLE templateFile) :
            Stream (
                CreateFile (
                    name,
                    desiredAccess,
                    shareMode,
                    securityAttributes,
                    creationDisposition,
                    flagsAndAttributes,
                    templateFile)) {}

        bool ClientNamedPipe::WaitForServer (
                const char *name,
                DWORD timeout) {
            return WaitNamedPipeW (name, timeout) == TRUE;
        }

    } // namespace stream
} // namespace thekogans

#endif // defined (TOOLCHAIN_OS_Windows)
