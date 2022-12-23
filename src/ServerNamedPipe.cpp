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
#include "thekogans/stream/ServerNamedPipe.h"

namespace thekogans {
    namespace stream {

        THEKOGANS_STREAM_IMPLEMENT_STREAM (ServerNamedPipe)

        ServerNamedPipe::ServerNamedPipe (
                const Address &address_,
                PipeType pipeType_) :
                address (address_),
                pipeType (pipeType_) {
            SECURITY_DESCRIPTOR sd;
            InitializeSecurityDescriptor (&sd, SECURITY_DESCRIPTOR_REVISION);
            SetSecurityDescriptorDacl (&sd, TRUE, 0, FALSE);
            SECURITY_ATTRIBUTES sa;
            sa.nLength = sizeof (SECURITY_ATTRIBUTES);
            sa.lpSecurityDescriptor = &sd;
            sa.bInheritHandle = FALSE;
            DWORD dwPipeMode = PIPE_WAIT;
            if (pipeType == Byte) {
                dwPipeMode |= PIPE_TYPE_BYTE | PIPE_READMODE_BYTE;
            }
            else {
                dwPipeMode |= PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE;
            }
            handle = CreateNamedPipeW (
                util::UTF8ToUTF16 (address.GetPath ()).c_str (),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                dwPipeMode,
                PIPE_UNLIMITED_INSTANCES,
                bufferSize,
                bufferSize,
                INFINITE,
                &sa);
            if (!IsOpen ()) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE);
            }
        }

    } // namespace stream
} // namespace thekogans

#endif // defined (TOOLCHAIN_OS_Windows)
