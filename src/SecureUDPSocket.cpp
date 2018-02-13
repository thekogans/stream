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

#if defined (THEKOGANS_STREAM_HAVE_OPENSSL)

#include <cassert>
#include "thekogans/util/LockGuard.h"
#include "thekogans/util/Exception.h"
#include "thekogans/util/LoggerMgr.h"
#include "thekogans/stream/AsyncIoEventQueue.h"
#include "thekogans/stream/AsyncIoEventSink.h"
#include "thekogans/stream/SecureUDPSocket.h"

namespace thekogans {
    namespace stream {

        THEKOGANS_UTIL_IMPLEMENT_HEAP_WITH_LOCK (SecureUDPSocket, util::SpinLock)

        util::ui32 SecureUDPSocket::Read (
                void *buffer,
                util::ui32 count) {
            if (buffer != 0 && count > 0) {
                int bytesRead = SSL_read (ssl.get (), buffer, count);
                if (bytesRead < 0) {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
                sessionInfo.countTransfered += bytesRead;
                return bytesRead;
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        util::ui32 SecureUDPSocket::Write (
                const void *buffer,
                util::ui32 count) {
            if (buffer != 0 && count > 0) {
                int bytesWritten = 0;
                if (IsAsync ()) {
                    {
                        util::LockGuard<util::SpinLock> guard (spinLock);
                        encryptList.push_back (
                            asyncInfo->eventSink.GetBuffer (
                                *this, util::HostEndian, buffer, count));
                    }
                    RunDTLS ();
                }
                else {
                    bytesWritten = SSL_write (ssl.get (), buffer, count);
                    if (bytesWritten < 0) {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
                    sessionInfo.countTransfered += bytesWritten;
                }
                return bytesWritten;
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        void SecureUDPSocket::WriteBuffer (util::Buffer::UniquePtr buffer) {
            if (buffer.get () != 0 && !buffer->IsEmpty ()) {
                if (IsAsync ()) {
                    {
                        util::LockGuard<util::SpinLock> guard (spinLock);
                        encryptList.push_back (std::move (buffer));
                    }
                    RunDTLS ();
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "%s", "WriteBuffer is called on a blocking socket.");
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

    #if defined (_MSC_VER)
        #pragma warning (push)
        #pragma warning (disable : 4302 4311)
    #endif // defined (_MSC_VER)

        void SecureUDPSocket::SessionConnect (
                SSL_CTX *ctx,
                const SessionInfo &sessionInfo_) {
            if (ctx != 0) {
                ssl.reset (SSL_new (ctx));
                sessionInfo = sessionInfo_;
                if (ssl.get () != 0 &&
                        (sessionInfo.serverName.empty () ||
                        SSL_set_tlsext_host_name (ssl.get (),
                            sessionInfo.serverName.c_str ()) == 1) &&
                        (sessionInfo.session.get () == 0 ||
                        SSL_set_session (ssl.get (),
                            sessionInfo.session.get ()) == 1)) {
                    if (IsAsync ()) {
                        assert (inBIO.get () != 0);
                        assert (outBIO.get () != 0);
                        CRYPTO_add (&inBIO->references, 1, CRYPTO_LOCK_BIO);
                        CRYPTO_add (&outBIO->references, 1, CRYPTO_LOCK_BIO);
                        SSL_set_bio (ssl.get (), inBIO.get (), outBIO.get ());
                    }
                    else {
                        BIO *bio = BIO_new_dgram ((int)handle, BIO_NOCLOSE);
                        if (bio != 0) {
                            /*
                            Address address = GetPeerAddress ();
                            BIO_ctrl (bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &address.address);
                            // FIXME: parametarize.
                            timeval timeout = util::TimeSpec::FromSeconds (3).Totimeval ();
                            BIO_ctrl (bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);
                            SSL_set_bio (ssl.get (), bio, bio);
                            */
                        }
                        else {
                            THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                        }
                    }
                    SSL_set_connect_state (ssl.get ());
                    SSL_set_ex_data (ssl.get (), OpenSSLInit::SSLSecureSocketIndex, this);
                    oldInfoCallback = SSL_get_info_callback (ssl.get ());
                    SSL_set_info_callback (ssl.get (), InfoCallback);
                    int result = SSL_connect (ssl.get ());
                    if (!IsFatalError (result)) {
                        if (IsAsync ()) {
                            RunDTLS ();
                        }
                    }
                    else {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
                }
                else {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        void SecureUDPSocket::SessionAccept (
                SSL_CTX *ctx,
                const SessionInfo &sessionInfo_) {
            if (ctx != 0) {
                ssl.reset (SSL_new (ctx));
                sessionInfo = sessionInfo_;
                if (ssl.get () != 0) {
                    if (IsAsync ()) {
                        assert (inBIO.get () != 0);
                        assert (outBIO.get () != 0);
                        CRYPTO_add (&inBIO->references, 1, CRYPTO_LOCK_BIO);
                        CRYPTO_add (&outBIO->references, 1, CRYPTO_LOCK_BIO);
                        SSL_set_bio (ssl.get (), inBIO.get (), outBIO.get ());
                    }
                    else if (SSL_set_fd (ssl.get (), (int)handle) != 1) {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
                    SSL_set_options (ssl.get (), SSL_OP_COOKIE_EXCHANGE);
                    SSL_set_accept_state (ssl.get ());
                    SSL_set_ex_data (ssl.get (),
                        OpenSSLInit::SSLSecureSocketIndex, this);
                    oldInfoCallback = SSL_get_info_callback (ssl.get ());
                    SSL_set_info_callback (ssl.get (), InfoCallback);
                    if (!IsAsync ()) {
                        int result = SSL_accept (ssl.get ());
                        if (IsFatalError (result)) {
                            THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                        }
                    }
                }
                else {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

    #if defined (_MSC_VER)
        #pragma warning (pop)
    #endif // defined (_MSC_VER)

        bool SecureUDPSocket::IsSessionReused () const {
            return SSL_session_reused (ssl.get ()) == 1;
        }

        void SecureUDPSocket::RenegotiateSession () {
            if (SSL_renegotiate (ssl.get ()) == 1) {
                int result = SSL_do_handshake (ssl.get ());
                if (!IsFatalError (result)) {
                    if (SSL_is_server (ssl.get ()) == 1) {
                        ssl->state = SSL_ST_ACCEPT;
                    }
                    if (IsAsync ()) {
                        RunDTLS ();
                    }
                    else if (SSL_is_server (ssl.get ()) == 1) {
                        result = SSL_do_handshake (ssl.get ());
                        if (IsFatalError (result)) {
                            THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                        }
                    }
                }
                else {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
            else {
                THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
            }
        }

        bool SecureUDPSocket::ShutdownCompleted () const {
            static const int mode = SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN;
            util::Flags<int> flags (SSL_get_shutdown (ssl.get ()));
            return sessionInfo.bidirectionalShutdown ? flags.Test (mode) : flags.TestAny (mode);
        }

        void SecureUDPSocket::ShutdownSession () {
            if (!ShutdownCompleted ()) {
                int result = SSL_shutdown (ssl.get ());
                if (result >= 0) {
                    if (IsAsync ()) {
                        RunDTLS ();
                    }
                    else if (!ShutdownCompleted ()) {
                        SSL_shutdown (ssl.get ());
                    }
                    if (ShutdownCompleted ()) {
                        ShutdownConnection ();
                    }
                }
                else {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
        }

        void SecureUDPSocket::InitAsyncIo () {
            inBIO.reset (BIO_new (BIO_s_mem ()));
            if (inBIO.get () != 0) {
                outBIO.reset (BIO_new (BIO_s_mem ()));
                if (outBIO.get () != 0) {
                    if (ssl.get () != 0) {
                        CRYPTO_add (&inBIO->references, 1, CRYPTO_LOCK_BIO);
                        CRYPTO_add (&outBIO->references, 1, CRYPTO_LOCK_BIO);
                        SSL_set_bio (ssl.get (), inBIO.get (), outBIO.get ());
                    }
                }
                else {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
            else {
                THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
            }
        #if defined (TOOLCHAIN_OS_Windows)
            PostAsyncRead (false);
        #else // defined (TOOLCHAIN_OS_Windows)
            SetBlocking (false);
            asyncInfo->AddStreamForEvents (AsyncInfo::EventRead);
        #endif // defined (TOOLCHAIN_OS_Windows)
        }

    #if defined (TOOLCHAIN_OS_Windows)
        void SecureUDPSocket::HandleOverlapped (AsyncInfo::Overlapped &overlapped) throw () {
            if (overlapped.event == AsyncInfo::EventRead) {
                THEKOGANS_UTIL_TRY {
                    AsyncInfo::ReadWriteOverlapped &readWriteOverlapped =
                        (AsyncInfo::ReadWriteOverlapped &)overlapped;
                    if (readWriteOverlapped.buffer.get () == 0) {
                        util::ui32 bufferLength = GetDataAvailable ();
                        if (bufferLength != 0) {
                            readWriteOverlapped.buffer.reset (
                                new util::Buffer (util::HostEndian, bufferLength));
                            readWriteOverlapped.buffer->AdvanceWriteOffset (
                                Read (readWriteOverlapped.buffer->GetWritePtr (), bufferLength));
                        }
                    }
                    if (readWriteOverlapped.buffer.get () != 0 &&
                            !readWriteOverlapped.buffer->IsEmpty ()) {
                        PostAsyncRead (false);
                        {
                            util::LockGuard<util::SpinLock> guard (spinLock);
                            decryptList.push_back (std::move (readWriteOverlapped.buffer));
                        }
                        RunDTLS ();
                    }
                    else {
                        asyncInfo->eventSink.HandleStreamDisconnect (*this);
                    }
                }
                THEKOGANS_UTIL_CATCH (util::Exception) {
                    THEKOGANS_UTIL_EXCEPTION_NOTE_LOCATION (exception);
                    asyncInfo->eventSink.HandleStreamError (*this, exception);
                }
            }
            else if (overlapped.event == AsyncInfo::EventWrite) {
                AsyncInfo::ReadWriteOverlapped &readWriteOverlapped =
                    (AsyncInfo::ReadWriteOverlapped &)overlapped;
                assert (readWriteOverlapped.buffer->IsEmpty ());
                asyncInfo->eventSink.HandleStreamWrite (
                    *this, std::move (readWriteOverlapped.buffer));
            }
        }
    #else // defined (TOOLCHAIN_OS_Windows)
        void SecureUDPSocket::HandleAsyncEvent (util::ui32 event) throw () {
            if (event == AsyncInfo::EventRead) {
                THEKOGANS_UTIL_TRY {
                    util::ui32 bufferLength = GetDataAvailable ();
                    if (bufferLength != 0) {
                        util::Buffer::UniquePtr buffer (
                            new util::Buffer (util::HostEndian, bufferLength));
                        if (buffer->AdvanceWriteOffset (
                                UDPSocket::Read (buffer->GetWritePtr (), bufferLength)) > 0) {
                            {
                                util::LockGuard<util::SpinLock> guard (spinLock);
                                decryptList.push_back (std::move (buffer));
                            }
                            RunDTLS ();
                        }
                    }
                    else {
                        asyncInfo->eventSink.HandleStreamDisconnect (*this);
                    }
                }
                THEKOGANS_UTIL_CATCH (util::Exception) {
                    THEKOGANS_UTIL_EXCEPTION_NOTE_LOCATION (exception);
                    asyncInfo->eventSink.HandleStreamError (*this, exception);
                }
            }
            else if (event == AsyncInfo::EventWrite) {
                asyncInfo->WriteBuffers ();
            }
        }
    #endif // defined (TOOLCHAIN_OS_Windows)

        void SecureUDPSocket::InfoCallback (
                const SSL *ssl,
                int where,
                int ret) {
            SecureUDPSocket *socket = (SecureUDPSocket *)SSL_get_ex_data (
                ssl, OpenSSLInit::SSLSecureSocketIndex);
            if (socket != 0) {
                util::Flags<int> flags (where);
                if (flags.Test (SSL_CB_HANDSHAKE_START) && ret == 1) {
                    if (socket->IsAsync ()) {
                        socket->asyncInfo->eventSink.HandleSecureUDPSocketHandshakeStarting (*socket);
                    }
                }
                else if (flags.Test (SSL_CB_HANDSHAKE_DONE) && ret == 1) {
                    socket->FinalizeConnection ();
                }
                else if (flags.Test (SSL_CB_READ_ALERT) && ret == 256) {
                    if (socket->IsAsync () && !socket->ShutdownCompleted ()) {
                        int result = SSL_shutdown (socket->ssl.get ());
                        if (result >= 0) {
                            socket->RunDTLS ();
                        }
                        else {
                            THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                        }
                    }
                    if (socket->ShutdownCompleted ()) {
                        socket->ShutdownConnection ();
                    }
                }
                // Chain the old InfoCallback.
                if (socket->oldInfoCallback != 0) {
                    socket->oldInfoCallback (ssl, where, ret);
                }
            }
        }

        void SecureUDPSocket::FinalizeConnection () {
            if (SSL_is_server (ssl.get ()) == 1) {
                if (IsSessionReused ()) {
                    SSL_SESSION *session = SSL_get0_session (ssl.get ());
                    if (session != 0) {
                        SessionInfo::UniquePtr savedSessionInfo (
                            (SessionInfo *)SSL_SESSION_get_ex_data (session,
                                OpenSSLInit::SSL_SESSIONSessionInfoIndex));
                        SSL_SESSION_set_ex_data (session,
                            OpenSSLInit::SSL_SESSIONSessionInfoIndex, 0);
                        if (savedSessionInfo.get () != 0) {
                            sessionInfo = *savedSessionInfo;
                        }
                    }
                }
                else {
                    // Guard against clients that don't support secure
                    // renegotiation.
                    if (SSL_get_secure_renegotiation_support (ssl.get ()) != 1) {
                        sessionInfo.renegotiationFrequency = util::UI32_MAX;
                    }
                    sessionInfo.countTransfered = 0;
                }
            }
            else {
                if (!sessionInfo.serverName.empty ()) {
                    int result = PostConnectionCheck (
                        ssl.get (), sessionInfo.serverName);
                    if (result != X509_V_OK) {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_AND_MESSAGE_EXCEPTION (
                            " (%s)", X509_verify_cert_error_string (result));
                    }
                }
                if (!IsSessionReused ()) {
                    // Guard against servers that don't support secure
                    // renegotiation.
                    if (SSL_get_secure_renegotiation_support (ssl.get ()) != 1) {
                        sessionInfo.renegotiationFrequency = util::UI32_MAX;
                    }
                    sessionInfo.countTransfered = 0;
                }
                sessionInfo.session.reset (SSL_get1_session (ssl.get ()));
            }
            if (IsAsync ()) {
                asyncInfo->eventSink.HandleSecureUDPSocketHandshakeCompleted (*this);
            }
        }

        void SecureUDPSocket::ShutdownConnection () {
            SSL_set_shutdown (ssl.get (), SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
            if (SSL_is_server (ssl.get ()) == 1) {
                SSL_SESSION *session = SSL_get0_session (ssl.get ());
                if (session != 0) {
                    SessionInfo::UniquePtr savedSessionInfo (new SessionInfo (sessionInfo));
                    if (SSL_SESSION_set_ex_data (
                            session,
                            OpenSSLInit::SSL_SESSIONSessionInfoIndex,
                            savedSessionInfo.get ()) == 1) {
                        savedSessionInfo.release ();
                    }
                }
            }
            else {
                sessionInfo.session.reset (SSL_get1_session (ssl.get ()));
            }
            if (IsAsync ()) {
                asyncInfo->eventSink.HandleSecureUDPSocketShutdownCompleted (*this);
            }
        }

        bool SecureUDPSocket::GetWorkToDo (
                util::Buffer *&decryptBuffer,
                util::Buffer *&encryptBuffer) {
            util::LockGuard<util::SpinLock> guard (spinLock);
            decryptBuffer = !decryptList.empty () ? decryptList.front ().get () : 0;
            encryptBuffer = !encryptList.empty () ? encryptList.front ().get () : 0;
            return
                decryptBuffer != 0 ||
                encryptBuffer != 0 ||
                BIO_ctrl_pending (outBIO.get ()) > 0;
        }

        void SecureUDPSocket::RunDTLS () {
            if (inRunDTLS.TryAcquire ()) {
                util::LockGuard<util::SpinLock> guard (inRunDTLS, false);
                util::Buffer *decryptBuffer = 0;
                util::Buffer *encryptBuffer = 0;
                while (GetWorkToDo (decryptBuffer, encryptBuffer)) {
                    // RECEIVE:
                    // We just received a buffer of cipher text from
                    // the socket. We shove this buffer in to the inBIO.
                    if (decryptBuffer != 0) {
                        assert (!decryptBuffer->IsEmpty ());
                        int bytesWritten = BIO_write (inBIO.get (),
                            decryptBuffer->GetReadPtr (),
                            (int)decryptBuffer->GetDataAvailableForReading ());
                        if (bytesWritten > 0) {
                            decryptBuffer->AdvanceReadOffset (bytesWritten);
                            if (decryptBuffer->IsEmpty ()) {
                                util::LockGuard<util::SpinLock> guard (spinLock);
                                decryptList.pop_front ();
                            }
                        }
                        else if (!BIO_should_retry (inBIO.get ())) {
                            asyncInfo->eventSink.HandleStreamError (*this,
                                THEKOGANS_CRYPTO_OPENSSL_EXCEPTION);
                            return;
                        }
                    }
                    // READ:
                    // Call SSL_read to let SSL perform it's magic.
                    // What comes out is plain text. We pass that on
                    // to the AsyncIoEventSink::HandleStreamRead.
                    int bytesRead = 0;
                    do {
                        util::Buffer::UniquePtr buffer =
                            asyncInfo->eventSink.GetBuffer (
                                *this, util::HostEndian, TLS_MAX_RECORD_LENGTH);
                        bytesRead = SSL_read (ssl.get (),
                            buffer->GetWritePtr (),
                            (int)buffer->GetDataAvailableForWriting ());
                        if (bytesRead > 0) {
                            sessionInfo.countTransfered += bytesRead;
                            buffer->AdvanceWriteOffset (bytesRead);
                            asyncInfo->eventSink.HandleStreamRead (
                                *this, std::move (buffer));
                        }
                        else if (IsFatalError (bytesRead)) {
                            asyncInfo->eventSink.HandleStreamError (*this,
                                THEKOGANS_CRYPTO_OPENSSL_EXCEPTION);
                            return;
                        }
                    } while (bytesRead > 0);
                    // WRITE:
                    // This is the encrypt side. We use SSL_write to
                    // encrypt plain text data waiting to be sent out.
                    if (encryptBuffer != 0) {
                        assert (!encryptBuffer->IsEmpty ());
                        int bytesWritten = SSL_write (ssl.get (),
                            encryptBuffer->GetReadPtr (),
                            (int)encryptBuffer->GetDataAvailableForReading ());
                        if (bytesWritten > 0) {
                            sessionInfo.countTransfered += bytesWritten;
                            encryptBuffer->AdvanceReadOffset (bytesWritten);
                            if (encryptBuffer->IsEmpty ()) {
                                util::LockGuard<util::SpinLock> guard (spinLock);
                                encryptList.pop_front ();
                            }
                        }
                        else if (IsFatalError (bytesWritten)) {
                            asyncInfo->eventSink.HandleStreamError (*this,
                                THEKOGANS_CRYPTO_OPENSSL_EXCEPTION);
                            return;
                        }
                    }
                    // SEND:
                    // This is the outBIO flush side. If we had data to
                    // encrypt, or openssl generated protocol data that
                    // needs to be handled, we drain the outBIO, and put
                    // it on the wire.
                    int bytesAvailable = (int)BIO_ctrl_pending (outBIO.get ());
                    if (bytesAvailable > 0) {
                        util::Buffer::UniquePtr buffer (
                            new util::Buffer (util::HostEndian, (std::size_t)bytesAvailable));
                        int bytesRead = BIO_read (outBIO.get (),
                            buffer->GetWritePtr (),
                            (int)buffer->GetDataAvailableForWriting ());
                        if (bytesRead > 0) {
                            buffer->AdvanceWriteOffset (bytesRead);
                            UDPSocket::WriteBuffer (std::move (buffer));
                        }
                        else if (!BIO_should_retry (outBIO.get ())) {
                            asyncInfo->eventSink.HandleStreamError (*this,
                                THEKOGANS_CRYPTO_OPENSSL_EXCEPTION);
                            return;
                        }
                    }
                }
            }
        }

        bool SecureUDPSocket::IsFatalError (int result) const {
            if (result <= 0) {
                long errorCode = SSL_get_error (ssl.get (), result);
                return
                    errorCode != SSL_ERROR_NONE &&
                    errorCode != SSL_ERROR_ZERO_RETURN &&
                    errorCode != SSL_ERROR_WANT_READ &&
                    errorCode != SSL_ERROR_WANT_WRITE;
            }
            return false;
        }

    } // namespace stream
} // namespace thekogans

#endif // defined (THEKOGANS_STREAM_HAVE_OPENSSL)
