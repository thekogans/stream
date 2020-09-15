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

#if defined (TOOLCHAIN_OS_Windows)
    #if !defined (_WINDOWS_)
        #if !defined (WIN32_LEAN_AND_MEAN)
            #define WIN32_LEAN_AND_MEAN
        #endif // !defined (WIN32_LEAN_AND_MEAN)
        #if !defined (NOMINMAX)
            #define NOMINMAX
        #endif // !defined (NOMINMAX)
        #include <windows.h>
    #endif // !defined (_WINDOWS_)
    #include <winsock2.h>
#endif // defined (TOOLCHAIN_OS_Windows)
#include <sstream>
#include <regex>
#include <openssl/x509v3.h>
#if defined (TOOLCHAIN_OS_Windows)
    #include "thekogans/util/WindowsUtils.h"
#endif // defined (TOOLCHAIN_OS_Windows)
#include "thekogans/util/SpinLock.h"
#include "thekogans/util/LockGuard.h"
#include "thekogans/util/Exception.h"
#include "thekogans/util/LoggerMgr.h"
#include "thekogans/util/StringUtils.h"
#include "thekogans/util/XMLUtils.h"
#include "thekogans/crypto/SystemCACertificates.h"
#include "thekogans/crypto/OpenSSLException.h"
#include "thekogans/stream/OpenSSLUtils.h"

namespace thekogans {
    namespace stream {

        void SSL_CTXDeleter::operator () (SSL_CTX *ctx) {
            if (ctx != 0) {
                SSL_CTX_free (ctx);
            }
        }

        void SSLDeleter::operator () (SSL *ssl) {
            if (ssl != 0) {
                SSL_free (ssl);
            }
        }

        void SSL_SESSIONDeleter::operator () (SSL_SESSION *session) {
            if (session != 0) {
                SSL_SESSION_free (session);
            }
        }

        namespace {
            void DeleteSessionInfo (
                    void *parent,
                    void *ptr,
                    CRYPTO_EX_DATA *ad,
                    int idx,
                    long argl,
                    void *argp) {
                volatile SessionInfo::Ptr sessionInfo ((SessionInfo *)ptr);
            }
        }

        int OpenSSLInit::SSLSecureSocketIndex = -1;
        int OpenSSLInit::SSL_SESSIONSessionInfoIndex = -1;
        util::SpinLock OpenSSLInit::spinLock;

        OpenSSLInit::OpenSSLInit (
                bool multiThreaded,
                util::ui32 entropyNeeded,
                util::ui64 workingSetSize,
                bool loadSystemCACertificates,
                bool loadSystemRootCACertificatesOnly) :
                crypto::OpenSSLInit (
                    multiThreaded,
                    entropyNeeded,
                    workingSetSize) {
            {
                util::LockGuard<util::SpinLock> guard (spinLock);
                if (SSLSecureSocketIndex == -1) {
                    SSLSecureSocketIndex = SSL_get_ex_new_index (0, 0, 0, 0, 0);
                    if (SSLSecureSocketIndex == -1) {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
                }
                if (SSL_SESSIONSessionInfoIndex == -1) {
                    SSL_SESSIONSessionInfoIndex =
                        SSL_SESSION_get_ex_new_index (0, 0, 0, 0, DeleteSessionInfo);
                    if (SSL_SESSIONSessionInfoIndex == -1) {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
                }
            }
            if (loadSystemCACertificates) {
                crypto::SystemCACertificates::Instance ().Load (loadSystemRootCACertificatesOnly);
            }
        }

        THEKOGANS_UTIL_IMPLEMENT_HEAP_WITH_LOCK (SessionInfo, util::SpinLock)

        const char * const SessionInfo::TAG_SESSION_INFO =
            "SessionInfo";
        const char * const SessionInfo::ATTR_SERVER_NAME =
            "ServerName";
        const char * const SessionInfo::ATTR_RENEGOTIATION_FREQUENCY =
            "RenegotiationFrequency";
        const char * const SessionInfo::ATTR_BIDIRECTIONAL_SHUTDOWN =
            "BidirectionalShutdown";
        const char * const SessionInfo::ATTR_COUNT_TRANSFERED =
            "CountTransfered";

        const SessionInfo SessionInfo::Empty;

        SessionInfo::SessionInfo (const SessionInfo &sessionInfo) :
                serverName (sessionInfo.serverName),
                renegotiationFrequency (sessionInfo.renegotiationFrequency),
                bidirectionalShutdown (sessionInfo.bidirectionalShutdown),
                countTransfered (sessionInfo.countTransfered),
                session (sessionInfo.session.get ()) {
            if (session.get () != 0) {
                CRYPTO_add (&session->references, 1, CRYPTO_LOCK_SSL_SESSION);
            }
        }

        SessionInfo &SessionInfo::operator = (
                const SessionInfo &sessionInfo) {
            if (&sessionInfo != this) {
                serverName = sessionInfo.serverName;
                renegotiationFrequency = sessionInfo.renegotiationFrequency;
                bidirectionalShutdown = sessionInfo.bidirectionalShutdown;
                countTransfered = sessionInfo.countTransfered;
                session.reset (sessionInfo.session.get ());
                if (session.get () != 0) {
                    CRYPTO_add (&session->references, 1, CRYPTO_LOCK_SSL_SESSION);
                }
            }
            return *this;
        }

        void SessionInfo::Parse (const pugi::xml_node &node) {
            serverName = util::Decodestring (node.attribute (ATTR_SERVER_NAME).value ());
            renegotiationFrequency = util::stringToui32 (node.attribute (ATTR_RENEGOTIATION_FREQUENCY).value ());
            bidirectionalShutdown = std::string (node.attribute (ATTR_BIDIRECTIONAL_SHUTDOWN).value ()) == util::XML_TRUE;
            countTransfered = util::stringToui32 (node.attribute (ATTR_COUNT_TRANSFERED).value ());
        }

        std::string SessionInfo::ToString (
                std::size_t indentationLevel,
                const char *tagName) const {
            if (tagName != 0) {
                util::Attributes attributes;
                attributes.push_back (
                    util::Attribute (
                        ATTR_SERVER_NAME,
                        util::Encodestring (serverName)));
                attributes.push_back (
                    util::Attribute (
                        ATTR_RENEGOTIATION_FREQUENCY,
                        util::size_tTostring (renegotiationFrequency)));
                attributes.push_back (
                    util::Attribute (
                        ATTR_BIDIRECTIONAL_SHUTDOWN,
                        bidirectionalShutdown ? util::XML_TRUE : util::XML_FALSE));
                attributes.push_back (
                    util::Attribute (
                        ATTR_COUNT_TRANSFERED,
                        util::size_tTostring (countTransfered)));
                return util::OpenTag (indentationLevel, tagName, attributes, true, true);
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        _LIB_THEKOGANS_STREAM_DECL const char * const OPENSSL_TLS_1_0 = "1.0";
        _LIB_THEKOGANS_STREAM_DECL const char * const OPENSSL_TLS_1_1 = "1.1";
        _LIB_THEKOGANS_STREAM_DECL const char * const OPENSSL_TLS_1_2 = "1.2";

        _LIB_THEKOGANS_STREAM_DECL const SSL_METHOD * _LIB_THEKOGANS_STREAM_API
        GetTLSMethod (const std::string &version) {
            if (version == OPENSSL_TLS_1_0) {
                return TLSv1_method ();
            }
            if (version == OPENSSL_TLS_1_1) {
                return TLSv1_1_method ();
            }
            if (version == OPENSSL_TLS_1_2) {
                return TLSv1_2_method ();
            }
            THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
        }

        _LIB_THEKOGANS_STREAM_DECL const char * const OPENSSL_DTLS_1_0 = "1.0";
        _LIB_THEKOGANS_STREAM_DECL const char * const OPENSSL_DTLS_1_2 = "1.2";

        _LIB_THEKOGANS_STREAM_DECL const SSL_METHOD * _LIB_THEKOGANS_STREAM_API
        GetDTLSMethod (const std::string &version) {
            if (version == OPENSSL_DTLS_1_0) {
                return DTLSv1_method ();
            }
            if (version == OPENSSL_DTLS_1_2) {
                return DTLSv1_2_method ();
            }
            THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
        }

        _LIB_THEKOGANS_STREAM_DECL int
        VerifyCallback (
                int ok,
                X509_STORE_CTX *store) {
            if (!ok) {
                int depth = X509_STORE_CTX_get_error_depth (store);
                int error = X509_STORE_CTX_get_error (store);
                const int MAX_NAME_LENGTH = 256;
                char issuer[MAX_NAME_LENGTH] = {0};
                char subject[MAX_NAME_LENGTH] = {0};
                X509 *cert = X509_STORE_CTX_get_current_cert (store);
                if (cert != 0) {
                    X509_NAME_oneline (X509_get_issuer_name (cert), issuer, sizeof (issuer));
                    X509_NAME_oneline (X509_get_subject_name (cert), subject, sizeof (subject));
                }
                else {
                    util::CopyString (issuer, MAX_NAME_LENGTH, "Unknown issuer.");
                    util::CopyString (subject, MAX_NAME_LENGTH, "Unknown subject.");
                }
                const char *message = X509_verify_cert_error_string (error);
                THEKOGANS_UTIL_LOG_SUBSYSTEM_ERROR (
                    THEKOGANS_STREAM,
                    "%s",
                    util::FormatString (
                        "Error with certificate at depth: %i\n"
                        "  issuer = %s\n"
                        "  subject = %s\n"
                        "  error %i:%s\n",
                        depth, issuer, subject, error,
                        message != 0 ? message : "Unknown error.").c_str ());
            }
            return ok;
        }

        namespace {
            bool CompareServerName (
                    const std::string &serverName,
                    const std::string &certificateName) {
                if (certificateName.find_first_of ('*') != std::string::npos) {
                    // This is a wildcard certificate. Do a regex match.
                    std::string patern;
                    for (std::size_t i = 0, count = certificateName.size (); i < count; ++i) {
                        if (certificateName[i] == '*') {
                            patern += ".+";
                        }
                        else if (certificateName[i] == '.') {
                            patern += "\\.";
                        }
                        else {
                            patern += certificateName[i];
                        }
                    }
                    return std::regex_match (serverName, std::regex (patern));
                }
                return util::StringCompareIgnoreCase (serverName.c_str (), certificateName.c_str ()) == 0;
            }

            bool CheckSubjectName (
                    X509 *cert,
                    const std::string &serverName) {
                char commonName[256] = {0};
                {
                    X509_NAME *subjectName = X509_get_subject_name (cert);
                    if (subjectName != 0) {
                        X509_NAME_get_text_by_NID (
                            subjectName, NID_commonName, commonName, sizeof (commonName));
                    }
                }
                return CompareServerName (serverName, commonName);
            }

            inline std::string GetExtensionName (X509_EXTENSION *extension) {
                return std::string (
                    (const char *)OBJ_nid2sn (
                        OBJ_obj2nid (X509_EXTENSION_get_object (extension))));
            }

            bool CheckSubjectAltName (
                    X509 *cert,
                    const std::string &serverName) {
                for (int i = 0, count = X509_get_ext_count (cert); i < count; ++i) {
                    X509_EXTENSION *extension = X509_get_ext (cert, i);
                    if (GetExtensionName (extension) == "subjectAltName") {
                        const X509V3_EXT_METHOD *method = X509V3_EXT_get (extension);
                        if (method != 0) {
                            void *extensionData = 0;
                            const void *data = extension->value->data;
                            if (method->it != 0) {
                                extensionData = ASN1_item_d2i (0,
                                    (const util::ui8 **)&data,
                                    extension->value->length,
                                    ASN1_ITEM_ptr (method->it));
                            }
                            else {
                                extensionData = method->d2i (0,
                                    (const util::ui8 **)&data,
                                    extension->value->length);
                            }
                            STACK_OF (CONF_VALUE) *nameValues =
                                method->i2v (method, extensionData, 0);
                            for (int j = 0, count = sk_CONF_VALUE_num (nameValues); j < count; ++j) {
                                CONF_VALUE *nameValue = sk_CONF_VALUE_value (nameValues, j);
                                if (std::string ("DNS") == nameValue->name &&
                                        CompareServerName (serverName, nameValue->value)) {
                                    return true;
                                }
                            }
                        }
                    }
                }
                return false;
            }
        }

        _LIB_THEKOGANS_STREAM_DECL int _LIB_THEKOGANS_STREAM_API
        PostConnectionCheck (
                SSL *ssl,
                const std::string &serverName) {
            crypto::X509Ptr cert (SSL_get_peer_certificate (ssl));
            return cert.get () != 0 &&
                (CheckSubjectName (cert.get (), serverName) ||
                    CheckSubjectAltName (cert.get (), serverName)) ?
                X509_V_OK : X509_V_ERR_APPLICATION_VERIFICATION;
        }

        _LIB_THEKOGANS_STREAM_DECL void _LIB_THEKOGANS_STREAM_API
        LoadCACertificates (
                SSL_CTX *ctx,
                const std::list<std::string> &caCertificates,
                pem_password_cb *passwordCallback,
                void *userData) {
            if (ctx != 0 && !caCertificates.empty ()) {
                crypto::X509_STOREPtr newStore;
                X509_STORE *store = SSL_CTX_get_cert_store (ctx);
                if (store == 0) {
                    newStore.reset (X509_STORE_new ());
                    if (newStore.get () != 0) {
                        store = newStore.get ();
                    }
                    else {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
                }
                for (std::list<std::string>::const_iterator
                        it = caCertificates.begin (),
                        end = caCertificates.end (); it != end; ++it) {
                    if (X509_STORE_add_cert (store,
                            crypto::ParseCertificate (
                                it->data (),
                                it->size (),
                                crypto::PEM_ENCODING,
                                passwordCallback,
                                userData).get ()) != 1) {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
                }
                if (newStore.get () != 0) {
                    SSL_CTX_set_cert_store (ctx, newStore.release ());
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        _LIB_THEKOGANS_STREAM_DECL void _LIB_THEKOGANS_STREAM_API
        LoadCertificateChain (
                SSL_CTX *ctx,
                const std::list<std::string> &certificateChain,
                pem_password_cb *passwordCallback,
                void *userData) {
            if (ctx != 0 && !certificateChain.empty ()) {
                std::list<std::string>::const_iterator it = certificateChain.begin ();
                const std::string &certificate = *it++;
                if (SSL_CTX_use_certificate (ctx,
                        crypto::ParseCertificate (
                            certificate.data (),
                            certificate.size (),
                            crypto::PEM_ENCODING,
                            passwordCallback,
                            userData).get ()) == 1) {
                    SSL_CTX_clear_chain_certs (ctx);
                    for (std::list<std::string>::const_iterator
                            end = certificateChain.end (); it != end; ++it) {
                        const std::string &certificate = *it;
                        if (SSL_CTX_add1_chain_cert (ctx,
                                crypto::ParseCertificate (
                                    certificate.data (),
                                    certificate.size (),
                                    crypto::PEM_ENCODING,
                                    passwordCallback,
                                    userData).get ()) != 1) {
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

        _LIB_THEKOGANS_STREAM_DECL void _LIB_THEKOGANS_STREAM_API
        LoadPrivateKey (
                SSL_CTX *ctx,
                const std::string &privateKey,
                pem_password_cb *passwordCallback,
                void *userData) {
            if (ctx != 0 && !privateKey.empty ()) {
                if (SSL_CTX_use_PrivateKey (ctx,
                        crypto::ParsePrivateKey (
                            privateKey.data (),
                            privateKey.size (),
                            crypto::PEM_ENCODING,
                            passwordCallback,
                            userData).get ()) != 1) {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        _LIB_THEKOGANS_STREAM_DECL void _LIB_THEKOGANS_STREAM_API
        LoadCipherList (
                SSL_CTX *ctx,
                const std::string &cipherList) {
            std::string trimmedCipherList = util::TrimSpaces (cipherList.c_str ());
            if (ctx != 0 && !trimmedCipherList.empty ()) {
                if (SSL_CTX_set_cipher_list (ctx, trimmedCipherList.c_str ()) != 1) {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        _LIB_THEKOGANS_STREAM_DECL void _LIB_THEKOGANS_STREAM_API
        LoadDHParams (
                SSL_CTX *ctx,
                const std::string &dhParams,
                pem_password_cb *passwordCallback,
                void *userData) {
            if (ctx != 0) {
                // DH params are optional.
                if (!dhParams.empty ()) {
                    SSL_CTX_set_options (ctx, SSL_CTX_get_options (ctx) | SSL_OP_SINGLE_DH_USE);
                    if (SSL_CTX_set_tmp_dh (ctx,
                            crypto::ParseDHParams (
                                dhParams.data (),
                                dhParams.size (),
                                crypto::PEM_ENCODING,
                                passwordCallback,
                                userData).get ()) != 1) {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        _LIB_THEKOGANS_STREAM_DECL void _LIB_THEKOGANS_STREAM_API
        LoadECDHParams (
                SSL_CTX *ctx,
                const std::string &ecdhParamsType,
                const std::string &ecdhParams,
                pem_password_cb *passwordCallback,
                void *userData) {
            if (ctx != 0) {
                // ECDH params are optional.
                if (ecdhParamsType == "auto") {
                    SSL_CTX_set_ecdh_auto (ctx, 1);
                }
                else if (ecdhParamsType == "curve") {
                    crypto::EC_KEYPtr ecdh (
                        EC_KEY_new_by_curve_name (OBJ_sn2nid (ecdhParams.c_str ())));
                    if (ecdh.get () == 0 || SSL_CTX_set_tmp_ecdh (ctx, ecdh.get ()) != 1) {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
                }
                else if (ecdhParamsType == crypto::PEM_ENCODING) {
                    crypto::EVP_PKEYPtr key = crypto::ParsePUBKEY (
                        ecdhParams.data (),
                        ecdhParams.size (),
                        crypto::PEM_ENCODING,
                        passwordCallback,
                        userData);
                    if (key.get () != 0) {
                        crypto::EC_KEYPtr ecdh (EVP_PKEY_get1_EC_KEY (key.get ()));
                        if (ecdh.get () == 0 || SSL_CTX_set_tmp_ecdh (ctx, ecdh.get ()) != 1) {
                            THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                        }
                    }
                    else {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

    } // namespace stream
} // namespace thekogans

#endif // defined (THEKOGANS_STREAM_HAVE_OPENSSL)
