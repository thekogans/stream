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

#if defined (TOOLCHAIN_OS_Linux)
    #include <sys/epoll.h>
#elif defined (TOOLCHAIN_OS_OSX)
    #include <sys/types.h>
    #include <sys/event.h>
    #include <sys/time.h>
#endif // defined (TOOLCHAIN_OS_Linux)
#include <cstdio>
#include <cstdarg>
#include <cassert>
#include "thekogans/util/XMLUtils.h"
#include "thekogans/util/Flags.h"
#include "thekogans/util/SpinLock.h"
#include "thekogans/util/LockGuard.h"
#include "thekogans/util/Exception.h"
#include "thekogans/util/LoggerMgr.h"
#include "thekogans/stream/AsyncIoEventQueue.h"
#include "thekogans/stream/AsyncIoEventSink.h"
#include "thekogans/stream/Stream.h"
#if defined (THEKOGANS_STREAM_TYPE_Static)
    #include "thekogans/stream/Pipe.h"
    #if defined (TOOLCHAIN_OS_Windows)
        #include "thekogans/stream/ClientNamedPipe.h"
        #include "thekogans/stream/ServerNamedPipe.h"
    #endif // defined (TOOLCHAIN_OS_Windows)
    #include "thekogans/stream/ClientTCPSocket.h"
    #include "thekogans/stream/ServerTCPSocket.h"
    #include "thekogans/stream/ClientUDPSocket.h"
    #include "thekogans/stream/ServerUDPSocket.h"
    #if defined (THEKOGANS_STREAM_HAVE_OPENSSL)
        #include "thekogans/stream/ClientSecureTCPSocket.h"
        #include "thekogans/stream/ServerSecureTCPSocket.h"
        #include "thekogans/stream/ClientSecureUDPSocket.h"
        #include "thekogans/stream/ServerSecureUDPSocket.h"
    #endif // defined (THEKOGANS_STREAM_HAVE_OPENSSL)
#endif // defined (THEKOGANS_STREAM_TYPE_Static)

namespace thekogans {
    namespace stream {

        const char * const Stream::Context::TAG_CONTEXT = "Context";
        const char * const Stream::Context::ATTR_TYPE = "Type";

        void Stream::Context::Parse (const pugi::xml_node &node) {
            type = util::Decodestring (node.attribute (ATTR_TYPE).value ());
        }

        std::string Stream::Context::ToString (
                std::size_t indentationLevel,
                const char *tagName) const {
            if (tagName != 0) {
                util::Attributes attributes;
                attributes.push_back (util::Attribute (ATTR_TYPE, util::Encodestring (type)));
                return util::OpenTag (indentationLevel, tagName, attributes, false, true);
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        Stream::Map &Stream::GetMap () {
            static Map map;
            return map;
        }

        Stream::MapInitializer::MapInitializer (
                const std::string &type,
                ContextFactory contextFactory) {
            std::pair<Map::iterator, bool> result =
                GetMap ().insert (Map::value_type (type, contextFactory));
            assert (result.second);
            if (!result.second) {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Duplicate Stream type: '%s'", type.c_str ());
            }
        }

        Stream::~Stream () {
            THEKOGANS_UTIL_TRY {
                Close ();
            }
            THEKOGANS_UTIL_CATCH_AND_LOG_SUBSYSTEM (THEKOGANS_STREAM)
        }

        Stream::Context::UniquePtr Stream::GetContext (const pugi::xml_node &node) {
            Map::iterator it = GetMap ().find (
                util::Decodestring (node.attribute (Context::ATTR_TYPE).value ()));
            return it != GetMap ().end () ?
                it->second (node) : Stream::Context::UniquePtr ();
        }

    #if defined (THEKOGANS_STREAM_TYPE_Static)
        void Stream::StaticInit () {
            static volatile bool registered = false;
            static util::SpinLock spinLock;
            if (!registered) {
                util::LockGuard<util::SpinLock> guard (spinLock);
                if (!registered) {
                #if defined (TOOLCHAIN_OS_Windows)
                    ClientNamedPipe::StaticInit ();
                    ServerNamedPipe::StaticInit ();
                #endif // defined (TOOLCHAIN_OS_Windows)
                    ClientTCPSocket::StaticInit ();
                    ServerTCPSocket::StaticInit ();
                    ClientUDPSocket::StaticInit ();
                    ServerUDPSocket::StaticInit ();
                #if defined (THEKOGANS_STREAM_HAVE_OPENSSL)
                    ClientSecureTCPSocket::StaticInit ();
                    ServerSecureTCPSocket::StaticInit ();
                    ClientSecureUDPSocket::StaticInit ();
                    ServerSecureUDPSocket::StaticInit ();
                #endif // defined (THEKOGANS_STREAM_HAVE_OPENSSL)
                    registered = true;
                }
            }
        }
    #endif // defined (THEKOGANS_STREAM_TYPE_Static)

        void Stream::Disconnect () {
            if (IsAsync ()) {
                asyncInfo->eventQueue.DeleteStream (*this);
            }
            else {
                Close ();
            }
        }

        void Stream::ReadFullBuffer (
                void *buffer,
                std::size_t count) {
            if (buffer != 0 && count > 0) {
                if (!IsAsync ()) {
                    util::ui8 *data = (util::ui8 *)buffer;
                    while (count > 0) {
                        std::size_t countRead = Read (data, count);
                        if (countRead > 0) {
                            data += countRead;
                            count -= countRead;
                        }
                        else {
                            THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                                "Unable to read buffer: %u", count);
                        }
                    }
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "%s", "ReadFullBuffer is called on an async stream.");
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        void Stream::WriteFullBuffer (
                const void *buffer,
                std::size_t count) {
            if (buffer != 0 && count > 0) {
                if (!IsAsync ()) {
                    const util::ui8 *data = (const util::ui8 *)buffer;
                    while (count > 0) {
                        std::size_t countWritten = Write (data, count);
                        if (countWritten > 0) {
                            data += countWritten;
                            count -= countWritten;
                        }
                        else {
                            THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                                "Unable to write buffer: %u", count);
                        }
                    }
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "%s", "WriteFullBuffer is called on an async stream.");
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        void Stream::Close () {
            if (IsOpen ()) {
            #if defined (TOOLCHAIN_OS_Windows)
                if (!::CloseHandle (handle)) {
            #else // defined (TOOLCHAIN_OS_Windows)
                if (close (handle) < 0) {
            #endif // defined (TOOLCHAIN_OS_Windows)
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_UTIL_OS_ERROR_CODE);
                }
                handle = THEKOGANS_UTIL_INVALID_HANDLE_VALUE;
            }
        }

        void Stream::HandleError (const util::Exception &exception) throw () {
            asyncInfo->eventSink.HandleStreamError (*this, exception);
        }

        THEKOGANS_UTIL_IMPLEMENT_HEAP_WITH_LOCK (Stream::AsyncInfo, util::SpinLock)

        const char * const Stream::AsyncInfo::EVENT_INVALID = "EventInvalid";
        const char * const Stream::AsyncInfo::EVENT_CONNECT = "EventConnect";
        const char * const Stream::AsyncInfo::EVENT_DISCONNECT = "EventDisconnect";
        const char * const Stream::AsyncInfo::EVENT_SHUTDOWN = "EventShutdown";
        const char * const Stream::AsyncInfo::EVENT_READ = "EventRead";
        const char * const Stream::AsyncInfo::EVENT_WRITE = "EventWrite";
        const char * const Stream::AsyncInfo::EVENT_READ_FROM = "EventReadFrom";
        const char * const Stream::AsyncInfo::EVENT_WRITE_TO = "EventWriteTo";
        const char * const Stream::AsyncInfo::EVENT_READ_MSG = "EventReadMsg";
        const char * const Stream::AsyncInfo::EVENT_WRITE_MSG = "EventWriteMsg";

        std::string Stream::AsyncInfo::eventToString (util::ui32 event) {
            return
                event == EventConnect ? EVENT_CONNECT :
                event == EventDisconnect ? EVENT_DISCONNECT :
                event == EventShutdown ? EVENT_SHUTDOWN :
                event == EventRead ? EVENT_READ :
                event == EventWrite ? EVENT_WRITE :
                event == EventReadFrom ? EVENT_READ_FROM :
                event == EventWriteTo ? EVENT_WRITE_TO :
                event == EventReadMsg ? EVENT_READ_MSG :
                event == EventWriteMsg ? EVENT_WRITE_MSG : EVENT_INVALID;
        }

        util::ui32 Stream::AsyncInfo::stringToEvent (const std::string &event) {
            return
                event == EVENT_CONNECT ? EventConnect :
                event == EVENT_DISCONNECT ? EventDisconnect :
                event == EVENT_SHUTDOWN ? EventShutdown :
                event == EVENT_READ ? EventRead :
                event == EVENT_WRITE ? EventWrite :
                event == EVENT_READ_FROM ? EventReadFrom :
                event == EVENT_WRITE_TO ? EventWriteTo :
                event == EVENT_READ_MSG ? EventReadMsg :
                event == EVENT_WRITE_MSG ? EventWriteMsg : EventInvalid;
        }

        Stream::AsyncInfo::AsyncInfo (
                AsyncIoEventQueue &eventQueue_,
                Stream &stream_,
                AsyncIoEventSink &eventSink_,
                std::size_t bufferLength_) :
                eventQueue (eventQueue_),
                stream (stream_),
                eventSink (eventSink_),
                bufferLength (bufferLength_),
            #if !defined (TOOLCHAIN_OS_Windows)
                events (EventInvalid),
                readDeadline (util::TimeSpec::Zero),
                writeDeadline (util::TimeSpec::Zero),
            #endif // !defined (TOOLCHAIN_OS_Windows)
                lastEventTime (util::TimeSpec::Zero) {
            eventSink.AddRef ();
        }

        Stream::AsyncInfo::~AsyncInfo () {
            eventSink.Release ();
            util::LockGuard<util::SpinLock> guard (spinLock);
        #if defined (TOOLCHAIN_OS_Windows)
            struct Callback : public OverlappedList::Callback {
                typedef OverlappedList::Callback::result_type result_type;
                typedef OverlappedList::Callback::argument_type argument_type;
                virtual result_type operator () (argument_type overlapped) {
                    delete overlapped;
                    return true;
                }
            } callback;
            overlappedList.clear (callback);
        #else // defined (TOOLCHAIN_OS_Windows)
            struct Callback : public BufferInfoList::Callback {
                typedef BufferInfoList::Callback::result_type result_type;
                typedef BufferInfoList::Callback::argument_type argument_type;
                virtual result_type operator () (argument_type bufferInfo) {
                    delete bufferInfo;
                    return true;
                }
            } callback;
            bufferInfoList.clear (callback);
        #endif // defined (TOOLCHAIN_OS_Windows)
        }

    #if defined (TOOLCHAIN_OS_Windows)
        Stream::AsyncInfo::Overlapped::Overlapped (
                Stream &stream_,
                util::ui32 event_) :
                stream (&stream_),
                event (event_),
                deadline (util::TimeSpec::Zero) {
            memset ((WSAOVERLAPPED *)this, 0, sizeof (WSAOVERLAPPED));
            if (util::Flags32 (event).TestAny (
                    Stream::AsyncInfo::EventRead |
                    Stream::AsyncInfo::EventReadFrom |
                    Stream::AsyncInfo::EventReadMsg)) {
                deadline = stream->GetReadTimeout ();
                if (deadline != util::TimeSpec::Zero) {
                    deadline += util::GetCurrentTime ();
                }
            }
            else if (util::Flags32 (event).TestAny (
                    Stream::AsyncInfo::EventConnect |
                    Stream::AsyncInfo::EventShutdown |
                    Stream::AsyncInfo::EventWrite |
                    Stream::AsyncInfo::EventWriteTo |
                    Stream::AsyncInfo::EventWriteMsg)) {
                deadline = stream->GetWriteTimeout ();
                if (deadline != util::TimeSpec::Zero) {
                    deadline += util::GetCurrentTime ();
                }
            }
            if (deadline != util::TimeSpec::Zero) {
                stream->asyncInfo->eventQueue.AddTimedStream (*stream);
            }
            stream->asyncInfo->AddOverlapped (this);
        }

        Stream::AsyncInfo::Overlapped::~Overlapped () {
            stream->asyncInfo->DeleteOverlapped (this);
            if (deadline != util::TimeSpec::Zero) {
                bool timed = false;
                {
                    util::LockGuard<util::SpinLock> guard (stream->asyncInfo->spinLock);
                    for (Overlapped *
                            overlapped = stream->asyncInfo->overlappedList.front ();
                            overlapped != 0;
                            overlapped = stream->asyncInfo->overlappedList.next (overlapped)) {
                        if (overlapped->deadline != util::TimeSpec::Zero) {
                            timed = true;
                            break;
                        }
                    }
                }
                if (!timed) {
                    stream->asyncInfo->eventQueue.DeleteTimedStream (*stream);
                }
            }
        }

        util::ui64 Stream::AsyncInfo::Overlapped::GetOffset () const {
            ULARGE_INTEGER offset;
            offset.LowPart = Offset;
            offset.HighPart = OffsetHigh;
            return offset.QuadPart;
        }

        void Stream::AsyncInfo::Overlapped::SetOffset (util::ui64 offset_) {
            ULARGE_INTEGER offset;
            offset.QuadPart = offset_;
            Offset = offset.LowPart;
            OffsetHigh = offset.HighPart;
        }

        THEKOGANS_UTIL_IMPLEMENT_HEAP_WITH_LOCK (Stream::AsyncInfo::ReadWriteOverlapped, util::SpinLock)

        Stream::AsyncInfo::ReadWriteOverlapped::ReadWriteOverlapped (
                Stream &stream,
                std::size_t count,
                bool useGetBuffer) :
                Overlapped (stream, Stream::AsyncInfo::EventRead),
                buffer (useGetBuffer ?
                    stream.asyncInfo->eventSink.GetBuffer (
                        stream,
                        util::HostEndian,
                        count) :
                    util::Buffer (util::HostEndian, count)),
                flags (0) {
            wsaBuf.len = (ULONG)buffer.GetDataAvailableForWriting ();
            wsaBuf.buf = (char *)buffer.GetWritePtr ();
        }

        Stream::AsyncInfo::ReadWriteOverlapped::ReadWriteOverlapped (
                Stream &stream,
                const void *buffer_,
                std::size_t count,
                bool useGetBuffer) :
                Overlapped (stream, Stream::AsyncInfo::EventWrite),
                buffer (useGetBuffer ?
                    stream.asyncInfo->eventSink.GetBuffer (
                        stream,
                        util::HostEndian,
                        buffer_,
                        count) :
                    util::Buffer (
                        util::HostEndian,
                        (const util::ui8 *)buffer_,
                        (const util::ui8 *)buffer_ + count)),
                flags (0) {
            wsaBuf.len = (ULONG)buffer.GetDataAvailableForReading ();
            wsaBuf.buf = (char *)buffer.GetReadPtr ();
        }

        void Stream::AsyncInfo::ReadWriteOverlapped::Epilog () throw () {
            switch (event) {
                case Stream::AsyncInfo::EventRead: {
                    buffer.AdvanceWriteOffset (GetCount ());
                    break;
                }
                case Stream::AsyncInfo::EventWrite: {
                    buffer.AdvanceReadOffset (GetCount ());
                    break;
                }
            }
        }

        void Stream::AsyncInfo::AddOverlapped (Overlapped *overlapped) {
            util::LockGuard<util::SpinLock> guard (spinLock);
            assert (!overlappedList.contains (overlapped));
            overlappedList.push_back (overlapped);
        }

        void Stream::AsyncInfo::DeleteOverlapped (Overlapped *overlapped) {
            util::LockGuard<util::SpinLock> guard (spinLock);
            assert (overlappedList.contains (overlapped));
            overlappedList.erase (overlapped);
        }

        THEKOGANS_UTIL_IMPLEMENT_HEAP_WITH_LOCK (Stream::TimedOverlapped, util::SpinLock)

        Stream::TimedOverlapped::TimedOverlapped () {
            memset ((OVERLAPPED *)this, 0, sizeof (OVERLAPPED));
            hEvent = CreateEvent (0, TRUE, FALSE, 0);
            if (hEvent == 0) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE);
            }
        }

        Stream::TimedOverlapped::~TimedOverlapped () {
            CloseHandle (hEvent);
        }

        DWORD Stream::TimedOverlapped::Wait (
                THEKOGANS_UTIL_HANDLE handle,
                const util::TimeSpec &timeSpec) {
            DWORD numberOfBytesTransferred = 0;
            DWORD result = WaitForSingleObject (hEvent, (DWORD)timeSpec.ToMilliseconds ());
            if (result == WAIT_OBJECT_0) {
                if (!GetOverlappedResult (handle, this, &numberOfBytesTransferred, FALSE)) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_UTIL_OS_ERROR_CODE);
                }
            }
            else {
                CancelIoEx (handle, this);
                if (result == WAIT_TIMEOUT) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_UTIL_OS_ERROR_CODE_TIMEOUT);
                }
                else if (result == WAIT_FAILED) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_UTIL_OS_ERROR_CODE);
                }
            }
            return numberOfBytesTransferred;
        }

        void Stream::HandleTimedOutOverlapped (AsyncInfo::Overlapped & /*overlapped*/) {
            HandleError (
                THEKOGANS_UTIL_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_TIMEOUT));
        }
    #else // defined (TOOLCHAIN_OS_Windows)
        THEKOGANS_UTIL_IMPLEMENT_HEAP_WITH_LOCK (
            Stream::AsyncInfo::WriteBufferInfo, util::SpinLock)

        Stream::AsyncInfo::WriteBufferInfo::WriteBufferInfo (
            Stream &stream_,
            const void *buffer_,
            std::size_t count,
            bool useGetBuffer) :
            BufferInfo (AsyncInfo::EventWrite),
            stream (stream_),
            buffer (useGetBuffer ?
                stream.asyncInfo->eventSink.GetBuffer (
                    stream,
                    util::HostEndian,
                    buffer_,
                    count) :
                util::Buffer (
                    util::HostEndian,
                    (const util::ui8 *)buffer_,
                    (const util::ui8 *)buffer_ + count)) {}

        ssize_t Stream::AsyncInfo::WriteBufferInfo::Write () {
            ssize_t countWritten = send (stream.handle,
                buffer.GetReadPtr (), buffer.GetDataAvailableForReading (), 0);
            if (countWritten > 0) {
                buffer.AdvanceReadOffset ((std::size_t)countWritten);
            }
            return countWritten;
        }

        bool Stream::AsyncInfo::WriteBufferInfo::Notify () {
            if (buffer.IsEmpty ()) {
                stream.asyncInfo->eventSink.HandleStreamWrite (
                    stream, std::move (buffer));
                return true;
            }
            return false;
        }

        void Stream::AsyncInfo::AddStreamForEvents (util::ui32 events) {
            eventQueue.AddStreamForEvents (stream, events);
        }

        void Stream::AsyncInfo::DeleteStreamForEvents (util::ui32 events) {
            eventQueue.DeleteStreamForEvents (stream, events);
        }

        void Stream::AsyncInfo::EnqBufferFront (BufferInfo::UniquePtr bufferInfo) {
            util::LockGuard<util::SpinLock> guard (spinLock);
            bufferInfoList.push_front (bufferInfo.get ());
            eventQueue.AddStreamForEvents (stream, bufferInfo.release ()->event);
        }

        void Stream::AsyncInfo::EnqBufferBack (BufferInfo::UniquePtr bufferInfo) {
            util::LockGuard<util::SpinLock> guard (spinLock);
            bufferInfoList.push_back (bufferInfo.get ());
            eventQueue.AddStreamForEvents (stream, bufferInfo.release ()->event);
        }

        Stream::AsyncInfo::BufferInfo::UniquePtr Stream::AsyncInfo::DeqBuffer () {
            util::LockGuard<util::SpinLock> guard (spinLock);
            BufferInfo::UniquePtr bufferInfo;
            if (!bufferInfoList.empty ()) {
                bufferInfo.reset (bufferInfoList.pop_front ());
                if (bufferInfoList.empty ()) {
                    eventQueue.DeleteStreamForEvents (
                        stream,
                        EventConnect |
                        EventShutdown |
                        EventWrite |
                        EventWriteTo |
                        EventWriteMsg);
                }
            }
            return bufferInfo;
        }

        void Stream::AsyncInfo::WriteBuffers () {
            for (BufferInfo::UniquePtr bufferInfo = DeqBuffer ();
                    bufferInfo.get () != 0; bufferInfo = DeqBuffer ()) {
                while (1) {
                    ssize_t countWritten = bufferInfo->Write ();
                    if (countWritten > 0) {
                        if (bufferInfo->Notify ()) {
                            break;
                        }
                    }
                    else if (countWritten == 0) {
                        eventSink.HandleStreamDisconnect (stream);
                        return;
                    }
                    else {
                        THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_STREAM_SOCKET_ERROR_CODE;
                        if (errorCode == EAGAIN || errorCode == EWOULDBLOCK) {
                            EnqBufferFront (std::move (bufferInfo));
                        }
                        else {
                            eventSink.HandleStreamError (stream,
                                THEKOGANS_UTIL_ERROR_CODE_EXCEPTION (errorCode));
                        }
                        return;
                    }
                }
            }
        }

        Stream::TimedEvent::TimedEvent () :
            #if defined (TOOLCHAIN_OS_Linux)
                handle (epoll_create (5)) {
            #else // defined (TOOLCHAIN_OS_Linux)
                handle (kqueue ()) {
            #endif // defined (TOOLCHAIN_OS_Linux)
            if (handle == THEKOGANS_UTIL_INVALID_HANDLE_VALUE) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE);
            }
        }

        Stream::TimedEvent::~TimedEvent () {
            close (handle);
        }

        bool Stream::TimedEvent::Wait (
                THEKOGANS_UTIL_HANDLE stream,
                util::ui32 event,
                const util::TimeSpec &timeSpec) {
            if (stream != THEKOGANS_UTIL_INVALID_HANDLE_VALUE &&
                    (event == Stream::AsyncInfo::EventRead || event == Stream::AsyncInfo::EventWrite) &&
                    timeSpec != util::TimeSpec::Infinite) {
            #if defined (TOOLCHAIN_OS_Linux)
                epoll_event epollEvent = {0};
                epollEvent.events = event == Stream::AsyncInfo::EventRead ? EPOLLIN : EPOLLOUT;
                if (epoll_ctl (handle, EPOLL_CTL_ADD, stream, &epollEvent) < 0) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_UTIL_OS_ERROR_CODE);
                }
                if (epoll_wait (handle, &epollEvent, 1, timeSpec.ToMilliseconds ()) == 1 &&
                        (((epollEvent.events & EPOLLIN) && event == Stream::AsyncInfo::EventRead) ||
                        ((epollEvent.events & EPOLLOUT) && event == Stream::AsyncInfo::EventWrite))) {
                    return true;
                }
            #else // defined (TOOLCHAIN_OS_Linux)
                keventStruct kevent = {0};
                keventSet (&kevent, stream,
                    event == Stream::AsyncInfo::EventRead ? EVFILT_READ : EVFILT_WRITE,
                    EV_ADD, 0, 0, 0);
                if (keventFunc (handle, &kevent, 1, 0, 0, 0) < 0) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_UTIL_OS_ERROR_CODE);
                }
                timespec timespec = timeSpec.Totimespec ();
                if (keventFunc (handle, 0, 0, &kevent, 1, &timespec) == 1 &&
                        (((kevent.filter == EVFILT_READ) && event == Stream::AsyncInfo::EventRead) ||
                        ((kevent.filter == EVFILT_WRITE) && event == Stream::AsyncInfo::EventWrite))) {
                    return true;
                }
            #endif // defined (TOOLCHAIN_OS_Linux)
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
            return false;
        }

        void Stream::HandleTimedOutAsyncEvent (util::ui32 /*event*/) throw () {
            HandleError (
                THEKOGANS_UTIL_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_TIMEOUT));
        }
    #endif // defined (TOOLCHAIN_OS_Windows)

        bool Stream::AsyncInfo::UpdateTimedStream (
                util::ui32 events,
                bool doBreak) {
            return eventQueue.UpdateTimedStream (stream, events, doBreak);
        }

    } // namespace stream
} // namespace thekogans
