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
#include "thekogans/stream/NamedPipe.h"

namespace thekogans {
    namespace stream {

        namespace {
            struct ReadOverlapped : public Overlapped {
                THEKOGANS_STREAM_DECLARE_OVERLAPPED (ReadOverlapped)

                util::Buffer buffer;

                ReadOverlapped (std::size_t bufferLength) :
                    buffer (util::NetworkEndian, bufferLength) {}

                virtual ssize_t Prolog (Stream & /*stream*/) throw () override {
                    return GetError () == ERROR_SUCCESS ? buffer.AdvanceWriteOffset (GetCount ()) : -1;
                }
            };

            THEKOGANS_STREAM_IMPLEMENT_OVERLAPPED (ReadOverlapped)
        }

        void NamedPipe::Read (std::size_t bufferLength) {
            if (bufferLength != 0) {
                std::unique_ptr<ReadOverlapped> overlapped (new ReadOverlapped (bufferLength));
                if (!ReadFile (
                        handle,
                        overlapped->buffer.GetWritePtr (),
                        (DWORD)overlapped->buffer.GetDataAvailableForWriting (),
                        0,
                        overlapped.get ())) {
                    THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_UTIL_OS_ERROR_CODE;
                    if (errorCode != ERROR_IO_PENDING) {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (errorCode);
                    }
                }
                overlapped.release ();
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        namespace {
            struct WriteOverlapped : public Overlapped {
                THEKOGANS_STREAM_DECLARE_OVERLAPPED (WriteOverlapped)

                util::Buffer buffer;

                WriteOverlapped (util::Buffer buffer_) :
                    buffer (std::move (buffer_)) {}

                virtual ssize_t Prolog (Stream & /*stream*/) throw () override {
                    return GetError () == ERROR_SUCCESS ? buffer.AdvanceReadOffset (GetCount ()) : -1;
                }
            };

            THEKOGANS_STREAM_IMPLEMENT_OVERLAPPED (WriteOverlapped)
        }

        void NamedPipe::Write (util::Buffer buffer) {
            if (!buffer.IsEmpty ()) {
                std::unique_ptr<WriteOverlapped> overlapped (new WriteOverlapped (std::move (buffer)));
                if (!WriteFile (
                        handle,
                        overlapped->buffer.GetReadPtr (),
                        (ULONG)overlapped->buffer.GetDataAvailableForReading (),
                        0,
                        overlapped.get ())) {
                    THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_UTIL_OS_ERROR_CODE;
                    if (errorCode != ERROR_IO_PENDING) {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (errorCode);
                    }
                }
                overlapped.release ();
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        void NamedPipe::SetMode (DWORD pipeMode) {
            if (!SetNamedPipeHandleState (handle, &pipeMode, 0, 0)) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE);
            }
        }

        void NamedPipe::HandleOverlapped (Overlapped &overlapped) throw () {
            if (overlapped.GetType () == ReadOverlapped::TYPE) {
                ReadOverlapped &readOverlapped = (ReadOverlapped &)overlapped;
                util::Producer<StreamEvents>::Produce (
                    std::bind (
                        &StreamEvents::OnStreamRead,
                        std::placeholders::_1,
                        Stream::SharedPtr (this),
                        std::move (readOverlapped.buffer)));
            }
            else if (overlapped.GetType () == WriteOverlapped::TYPE) {
                WriteOverlapped &writeOverlapped = (WriteOverlapped &)overlapped;
                util::Producer<StreamEvents>::Produce (
                    std::bind (
                        &StreamEvents::OnStreamWrite,
                        std::placeholders::_1,
                        Stream::SharedPtr (this),
                        std::move (writeOverlapped.buffer)));
            }
        }

    } // namespace stream
} // namespace thekogans

#endif // defined (TOOLCHAIN_OS_Windows)
