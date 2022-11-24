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

#if !defined (__thekogans_stream_AsyncIoEventSink_h)
#define __thekogans_stream_AsyncIoEventSink_h

#include <memory>
#include "thekogans/util/Environment.h"
#include "thekogans/util/Types.h"
#include "thekogans/util/RefCounted.h"
#include "thekogans/util/Buffer.h"
#include "thekogans/util/Exception.h"
#include "thekogans/stream/Config.h"
#include "thekogans/stream/Address.h"
#include "thekogans/stream/TCPSocket.h"
#include "thekogans/stream/ServerUDPSocket.h"
#if defined (THEKOGANS_STREAM_HAVE_OPENSSL)
    #include "thekogans/stream/SecureTCPSocket.h"
    #include "thekogans/stream/SecureUDPSocket.h"
#endif // defined (THEKOGANS_STREAM_HAVE_OPENSSL)

namespace thekogans {
    namespace stream {

    #if defined (TOOLCHAIN_OS_Windows)
        struct ClientNamedPipe;
        struct ServerNamedPipe;
    #endif // defined (TOOLCHAIN_OS_Windows)
        struct ServerTCPSocket;
    #if defined (THEKOGANS_STREAM_HAVE_OPENSSL)
        struct ServerSecureTCPSocket;
        struct ServerSecureUDPSocket;
    #endif // defined (THEKOGANS_STREAM_HAVE_OPENSSL)

        /// \struct AsyncIoEventSink AsyncIoEventSink.h thekogans/stream/AsyncIoEventSink.h
        ///
        /// \brief
        /// AsyncIoEventSink represents the callback mechanism by which async io events
        /// are delivered. AsyncIoEventSinks can be chained together to provide a filtering
        /// pipeline.
        ///
        /// IMPORTANT NOTE: This api is called asynchronously, and because of that, there
        /// are some restrictions on what is considered in good taste. The following are
        /// very much encouraged:
        /// - Do be quick about it:
        ///   - Queue a job on a \see{thekogans::util::JobQueue}!
        ///   - Schedule a job on a \see{thekogans::util::Scheduler}!
        ///   - Prime a \see{thekogans::util::Pipeline} stage!
        ///   - Borrow a \see{thekogans::util::JobQueue} from a
        ///     \see{thekogans::util::JobQueuePool}!
        /// - About the only sensible thing to do when responding
        ///   to \see{AsyncIoEventSink::HandleStreamError} and
        ///   \see{AsyncIoEventSink::HandleStreamDisconnect} is to call
        ///   \see{AsyncIoEventQueue::DeleteStream} to aggregate it for
        ///   deletion (after \see{AsyncIoEventQueue::WaitForEvents}
        ///   returns). Please consult any one of the \see{TCPSocket}
        ///   based examples provided with thekogans_stream to see the
        ///   right way to do this. The one exception to this rule is
        ///   when processing THEKOGANS_UTIL_OS_ERROR_CODE_TIMEOUT. In
        ///   some situations it's appropriate to escalate the timeout
        ///   a few times before giving up.
        /// - Honor the throw ()!
        ///   This last one cannot be over stressed. Again, you are being
        ///   called asynchronously from a completely different thread.
        ///   There is no one there to catch your exceptions. YOU WILL SEG FAULT!

        struct _LIB_THEKOGANS_STREAM_DECL AsyncIoEventSink : public virtual util::RefCounted {
            /// \brief
            /// Declare \see{util::RefCounted} pointers.
            THEKOGANS_UTIL_DECLARE_REF_COUNTED_POINTERS (AsyncIoEventSink)

        #if defined (THEKOGANS_STREAM_HAVE_OPENSSL)
            /// \brief
            /// Override this method if you're deriving from a \see{SecureTCPSocket}.
            /// \param[in] handle OS socket handle to wrap.
            /// \return A SecureTCPSocket derivative.
            virtual SecureTCPSocket::SharedPtr GetSecureTCPSocket (THEKOGANS_UTIL_HANDLE handle) {
                return SecureTCPSocket::SharedPtr (new SecureTCPSocket (handle));
            }


        #endif // defined (THEKOGANS_STREAM_HAVE_OPENSSL)

        };

    } // namespace stream
} // namespace thekogans

#endif // !defined (__thekogans_stream_AsyncIoEventSink_h)
