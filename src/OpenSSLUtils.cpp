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
    #endif // !defined (_WINDOWS_)
    #include <winsock2.h>
    #include <wincrypt.h>
    #include <windows.h>
#elif defined (TOOLCHAIN_OS_OSX)
    #include <CoreFoundation/CoreFoundation.h>
    #include <Security/Security.h>
#endif // defined (TOOLCHAIN_OS_Windows)
#include <sstream>
#include <regex>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#if defined (TOOLCHAIN_OS_Windows)
    #include "thekogans/util/WindowsUtils.h"
#endif // defined (TOOLCHAIN_OS_Windows)
#include "thekogans/util/OwnerVector.h"
#include "thekogans/util/Buffer.h"
#include "thekogans/util/SpinLock.h"
#include "thekogans/util/Thread.h"
#include "thekogans/util/RandomSource.h"
#include "thekogans/util/Exception.h"
#include "thekogans/util/LoggerMgr.h"
#include "thekogans/util/StringUtils.h"
#if defined (THEKOGANS_STREAM_HAVE_PUGIXML)
    #include "thekogans/util/XMLUtils.h"
#endif // defined (THEKOGANS_STREAM_HAVE_PUGIXML)
#include "thekogans/stream/SecureTCPSocket.h"
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

        void BIODeleter::operator () (BIO *bio) {
            if (bio != 0) {
                BIO_free (bio);
            }
        }

        void X509Deleter::operator () (X509 *x509) {
            if (x509 != 0) {
                X509_free (x509);
            }
        }

        void X509_STOREDeleter::operator () (X509_STORE *store) {
            if (store != 0) {
                X509_STORE_free (store);
            }
        }

        void X509_CRLDeleter::operator () (X509_CRL *crl) {
            if (crl != 0) {
                X509_CRL_free (crl);
            }
        }

        void DHDeleter::operator () (DH *dh) {
            if (dh != 0) {
                DH_free (dh);
            }
        }

        void EVP_PKEYDeleter::operator () (EVP_PKEY *key) {
            if (key != 0) {
                EVP_PKEY_free (key);
            }
        }

        void EC_KEYDeleter::operator () (EC_KEY *key) {
            if (key != 0) {
                EC_KEY_free (key);
            }
        }

        void DSADeleter::operator () (DSA *dsa) {
            if (dsa != 0) {
                DSA_free (dsa);
            }
        }

        OpenSSLAllocator OpenSSLAllocator::Global;

        void *OpenSSLAllocator::Alloc (std::size_t size) {
            return size > 0 ? OPENSSL_malloc (size) : 0;
        }

        void OpenSSLAllocator::Free (
                void *ptr,
                std::size_t /*size*/) {
            if (ptr != 0) {
                OPENSSL_free (ptr);
            }
        }

        namespace {
            util::OwnerVector<util::SpinLock> staticLocks;

            void LockingFunction (
                    int mode,
                    int lockIndex,
                    const char *file,
                    int line) {
                if (mode & CRYPTO_LOCK) {
                    staticLocks[lockIndex]->Acquire ();
                }
                else {
                    staticLocks[lockIndex]->Release ();
                }
            }

            unsigned long IdFunction () {
                return (unsigned long)(unsigned long long)util::Thread::GetCurrThreadHandle ();
            }

            struct CRYPTO_dynlock_value *DynlockCreateFunction (
                    const char *file,
                    int line) {
                return (struct CRYPTO_dynlock_value *)new util::SpinLock;
            }

            void DynlockLockFunction (
                    int mode,
                    struct CRYPTO_dynlock_value *lock,
                    const char *file,
                    int line) {
                if (mode & CRYPTO_LOCK) {
                    reinterpret_cast<util::SpinLock *> (lock)->Acquire ();
                }
                else {
                    reinterpret_cast<util::SpinLock *> (lock)->Release ();
                }
            }

            void DynlockDestroyFunction (
                    struct CRYPTO_dynlock_value *lock,
                    const char *file,
                    int line) {
                delete reinterpret_cast<util::SpinLock *> (lock);
            }

            void DeleteSessionInfo (
                    void *parent,
                    void *ptr,
                    CRYPTO_EX_DATA *ad,
                    int idx,
                    long argl,
                    void *argp) {
                volatile SessionInfo::UniquePtr sessionInfo ((SessionInfo *)ptr);
            }

            void ExitFunc (THEKOGANS_UTIL_THREAD_HANDLE thread) {
                CRYPTO_THREADID threadId;
                CRYPTO_THREADID_set_numeric (&threadId, (unsigned long)(unsigned long long)thread);
                ERR_remove_thread_state (&threadId);
            }

        #if defined (TOOLCHAIN_OS_Windows)
            std::string GetCertName (PCERT_NAME_BLOB certName) {
                DWORD size = CertNameToStr (
                    X509_ASN_ENCODING,
                    certName,
                    CERT_SIMPLE_NAME_STR,
                    0, 0);
                if (size != 0) {
                    std::vector<char> buffer (size);
                    CertNameToStr (
                        X509_ASN_ENCODING,
                        certName,
                        CERT_SIMPLE_NAME_STR,
                        &buffer[0],
                        (DWORD)buffer.size ());
                    return std::string (&buffer[0]);
                }
                return std::string ();
            }
        #elif defined (TOOLCHAIN_OS_OSX)
            struct CFArrayRefDeleter {
                void operator () (CFArrayRef arrayRef) {
                    if (arrayRef != 0) {
                        CFRelease (arrayRef);
                    }
                }
            };
            typedef std::unique_ptr<const __CFArray, CFArrayRefDeleter> CFArrayRefPtr;

            struct CFDictionaryRefDeleter {
                void operator () (CFDictionaryRef dictionaryRef) {
                    if (dictionaryRef != 0) {
                        CFRelease (dictionaryRef);
                    }
                }
            };
            typedef std::unique_ptr<const __CFDictionary, CFDictionaryRefDeleter> CFDictionaryRefPtr;

            struct CFErrorRefDeleter {
                void operator () (CFErrorRef errorRef) {
                    if (errorRef != 0) {
                        CFRelease (errorRef);
                    }
                }
            };
            typedef std::unique_ptr<__CFError, CFErrorRefDeleter> CFErrorRefPtr;

            struct CFDataRefDeleter {
                void operator () (CFDataRef dataRef) {
                    if (dataRef != 0) {
                        CFRelease (dataRef);
                    }
                }
            };
            typedef std::unique_ptr<const __CFData, CFDataRefDeleter> CFDataRefPtr;

            struct CFDateRefDeleter {
                void operator () (CFDateRef dateRef) {
                    if (dateRef != 0) {
                        CFRelease (dateRef);
                    }
                }
            };
            typedef std::unique_ptr<const __CFDate, CFDateRefDeleter> CFDateRefPtr;

            bool CheckDateRange (
                    CFNumberRef notBefore,
                    CFNumberRef notAfter) {
                CFDateRefPtr now (CFDateCreate (0, CFAbsoluteTimeGetCurrent ()));
                if (now.get () != 0) {
                    CFAbsoluteTime validityNotBefore;
                    CFAbsoluteTime validityNotAfter;
                    if (CFNumberGetValue (notBefore, kCFNumberDoubleType, &validityNotBefore) &&
                            CFNumberGetValue (notAfter, kCFNumberDoubleType, &validityNotAfter)) {
                        CFDateRefPtr notBeforeDate (CFDateCreate (0, validityNotBefore));
                        CFDateRefPtr notAfterDate (CFDateCreate (0, validityNotAfter));
                        return notBeforeDate.get () != 0 && notAfterDate.get () != 0 &&
                            CFDateCompare (notBeforeDate.get (), now.get (), 0) == kCFCompareLessThan &&
                            CFDateCompare (now.get (), notAfterDate.get (), 0) == kCFCompareLessThan;
                    }
                }
                return false;
            }
        #endif // defined (TOOLCHAIN_OS_OSX)

            struct SystemCACertificates : public util::Singleton<SystemCACertificates, util::SpinLock> {
                std::list<X509Ptr> certificates;
                util::SpinLock spinLock;

                void Load (bool loadSystemRootCACertificatesOnly = true) {
                    util::LockGuard<util::SpinLock> guard (spinLock);
                    certificates.clear ();
                #if defined (TOOLCHAIN_OS_Windows)
                    struct SystemStore {
                        HCERTSTORE certStore;
                        explicit SystemStore (const char *storeName) :
                                certStore (CertOpenSystemStore (0, storeName)) {
                            if (certStore == 0) {
                                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                                    THEKOGANS_UTIL_OS_ERROR_CODE);
                            }
                        }
                        ~SystemStore () {
                            CertCloseStore (certStore, 0);
                        }
                    };
                    SystemStore rootStore ("ROOT");
                    SystemStore caStore ("CA");
                    SystemStore myStore ("MY");
                    SystemStore *stores[] = {
                        &rootStore,
                        &caStore,
                        &myStore
                    };
                    for (int i = 0, numStores = THEKOGANS_UTIL_ARRAY_SIZE (stores); i < numStores; ++i) {
                        PCCERT_CONTEXT certContext = 0;
                        while ((certContext = CertEnumCertificatesInStore (stores[i]->certStore, certContext)) != 0) {
                            // Skip expired certificates.
                            if (CertVerifyTimeValidity (0, certContext->pCertInfo) == 0) {
                                if (loadSystemRootCACertificatesOnly) {
                                    // We only want to add Root CAs, so make
                                    // sure Subject and Issuer names match.
                                    std::string subject =
                                        GetCertName (&certContext->pCertInfo->Subject);
                                    std::string issuer =
                                        GetCertName (&certContext->pCertInfo->Issuer);
                                    if (subject.empty () || issuer.empty () || subject != issuer) {
                                        continue;
                                    }
                                }
                                // M$ certificates are DER encoded.
                                X509Ptr certificate =
                                    ParseDERCertificate (
                                        certContext->pbCertEncoded,
                                        certContext->cbCertEncoded);
                                if (certificate.get () != 0) {
                                    certificates.push_back (std::move (certificate));
                                }
                                else {
                                    THEKOGANS_STREAM_THROW_OPENSSL_EXCEPTION;
                                }
                            }
                        }
                    }
                #elif defined (TOOLCHAIN_OS_Linux)
                    // FIXME: implement
                    assert (0);
                #elif defined (TOOLCHAIN_OS_OSX)
                    // This code was adapted from: https://github.com/raggi/openssl-osx-ca
                    // Get certificates from all domains, not just System, this lets
                    // the user add CAs to their "login" keychain, and Admins to add
                    // to the "System" keychain
                    SecTrustSettingsDomain domains[] = {
                        kSecTrustSettingsDomainSystem,
                        kSecTrustSettingsDomainAdmin,
                        kSecTrustSettingsDomainUser
                    };
                    CFStringRef x509OID[] = {
                        kSecOIDX509V1ValidityNotBefore,
                        kSecOIDX509V1ValidityNotAfter,
                        kSecOIDX509V1SubjectName,
                        kSecOIDX509V1IssuerName
                    };
                    CFArrayRefPtr x509Keys (
                        CFArrayCreate (0,
                            (const void **)x509OID,
                            THEKOGANS_UTIL_ARRAY_SIZE (x509OID),
                            &kCFTypeArrayCallBacks));
                    for (int i = 0, numDomains = THEKOGANS_UTIL_ARRAY_SIZE (domains); i < numDomains; ++i) {
                        CFArrayRef certs = 0;
                        OSStatus errorCode = SecTrustSettingsCopyCertificates (domains[i], &certs);
                        if (certs != 0) {
                            CFArrayRefPtr certsPtr (certs);
                            for (int j = 0, numCerts = CFArrayGetCount (certs); j < numCerts; ++j) {
                                SecCertificateRef cert = (SecCertificateRef)CFArrayGetValueAtIndex (certs, j);
                                if (cert != 0) {
                                    CFErrorRef error = 0;
                                    CFDictionaryRefPtr names (
                                        SecCertificateCopyValues (cert, x509Keys.get (), &error));
                                    if (names != 0) {
                                        // Check if the certificate expired.
                                        CFNumberRef notBefore =
                                            (CFNumberRef)CFDictionaryGetValue (
                                                (CFDictionaryRef)CFDictionaryGetValue (
                                                    names.get (),
                                                    kSecOIDX509V1ValidityNotBefore),
                                                kSecPropertyKeyValue);
                                        CFNumberRef notAfter =
                                            (CFNumberRef)CFDictionaryGetValue (
                                                (CFDictionaryRef)CFDictionaryGetValue (
                                                    names.get (),
                                                    kSecOIDX509V1ValidityNotAfter),
                                                kSecPropertyKeyValue);
                                        if (notBefore != 0 && notAfter != 0 && CheckDateRange (notBefore, notAfter)) {
                                            if (loadSystemRootCACertificatesOnly) {
                                                // We only want to add Root CAs, so make
                                                // sure Subject and Issuer names match.
                                                CFStringRef issuer =
                                                    (CFStringRef)CFDictionaryGetValue (
                                                        (CFDictionaryRef)CFDictionaryGetValue (
                                                            names.get (),
                                                            kSecOIDX509V1IssuerName),
                                                        kSecPropertyKeyValue);
                                                CFStringRef subject =
                                                    (CFStringRef)CFDictionaryGetValue(
                                                        (CFDictionaryRef)CFDictionaryGetValue (
                                                            names.get (),
                                                            kSecOIDX509V1SubjectName),
                                                        kSecPropertyKeyValue);
                                                if (issuer == 0 || subject == 0 || !CFEqual (subject, issuer)) {
                                                    continue;
                                                }
                                            }
                                            CFDataRef data = 0;
                                            errorCode =
                                                SecItemExport (cert, kSecFormatX509Cert, kSecItemPemArmour, 0, &data);
                                            if (data != 0) {
                                                CFDataRefPtr dataPtr (data);
                                                // Apple certificates are PEM encoded.
                                                X509Ptr certificate =
                                                    ParsePEMCertificate (
                                                        CFDataGetBytePtr (data),
                                                        CFDataGetLength (data));
                                                if (certificate.get () != 0) {
                                                    certificates.push_back (std::move (certificate));
                                                }
                                                else {
                                                    THEKOGANS_STREAM_THROW_OPENSSL_EXCEPTION;
                                                }
                                            }
                                            else if (errorCode != noErr) {
                                                THEKOGANS_UTIL_THROW_OSSTATUS_ERROR_CODE_EXCEPTION (errorCode);
                                            }
                                        }
                                    }
                                    else if (error != 0) {
                                        CFErrorRefPtr errorPtr (error);
                                        THEKOGANS_UTIL_THROW_CFERRORREF_EXCEPTION (error);
                                    }
                                }
                            }
                        }
                    }
                #endif // defined (TOOLCHAIN_OS_Windows)
                }

                void Use (SSL_CTX *ctx) {
                    util::LockGuard<util::SpinLock> guard (spinLock);
                    X509_STOREPtr newStore;
                    X509_STORE *store = SSL_CTX_get_cert_store (ctx);
                    if (store == 0) {
                        newStore.reset (X509_STORE_new ());
                        if (newStore.get () != 0) {
                            store = newStore.get ();
                        }
                        else {
                            THEKOGANS_STREAM_THROW_OPENSSL_EXCEPTION;
                        }
                    }
                    for (std::list<X509Ptr>::const_iterator
                            it = certificates.begin (),
                            end = certificates.end (); it != end; ++it) {
                        if (X509_STORE_add_cert (store, (*it).get ()) != 1) {
                            THEKOGANS_STREAM_THROW_OPENSSL_EXCEPTION;
                        }
                    }
                    if (newStore.get () != 0) {
                        SSL_CTX_set_cert_store (ctx, newStore.release ());
                    }
                }

                void Flush () {
                    util::LockGuard<util::SpinLock> guard (spinLock);
                    certificates.clear ();
                }
            };
        }

        int OpenSSLInit::SSLSecureSocketIndex = -1;
        int OpenSSLInit::SSL_SESSIONSessionInfoIndex = -1;

        // This is enough entropy to cover 512 bit keys.
        OpenSSLInit::OpenSSLInit (
                bool multiThreaded,
                util::ui32 entropyNeeded,
                bool loadSystemCACertificates,
                bool loadSystemRootCACertificatesOnly) {
            if (multiThreaded) {
                int lockCount = CRYPTO_num_locks ();
                if (lockCount > 0) {
                    staticLocks.resize (lockCount);
                    for (int i = 0; i < lockCount; ++i) {
                        staticLocks[i] = new util::SpinLock;
                    }
                }
                // Static lock callbacks.
                CRYPTO_set_locking_callback (LockingFunction);
                CRYPTO_set_id_callback (IdFunction);
                // Dynamic locks callbacks.
                CRYPTO_set_dynlock_create_callback (DynlockCreateFunction);
                CRYPTO_set_dynlock_lock_callback (DynlockLockFunction);
                CRYPTO_set_dynlock_destroy_callback (DynlockDestroyFunction);
            }
            SSL_library_init ();
            SSL_load_error_strings ();
            OpenSSL_add_all_algorithms ();
            if (entropyNeeded >= MIN_ENTROPY_NEEDED) {
                util::SecureBuffer entropy (util::HostEndian, entropyNeeded);
                {
                    util::RandomSource randomSource;
                    randomSource.GetBytes (entropy.data, entropy.length);
                }
                RAND_seed (entropy.data, (int)entropy.length);
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Not enough entropy: %u < %u",
                    entropyNeeded, MIN_ENTROPY_NEEDED);
            }
            SSLSecureSocketIndex =
                SSL_get_ex_new_index (0, 0, 0, 0, 0);
            if (SSLSecureSocketIndex == -1) {
                THEKOGANS_STREAM_THROW_OPENSSL_EXCEPTION;
            }
            SSL_SESSIONSessionInfoIndex =
                SSL_SESSION_get_ex_new_index (0, 0, 0, 0, DeleteSessionInfo);
            if (SSL_SESSIONSessionInfoIndex == -1) {
                THEKOGANS_STREAM_THROW_OPENSSL_EXCEPTION;
            }
            if (loadSystemCACertificates) {
                SystemCACertificates::Instance ().Load (loadSystemRootCACertificatesOnly);
            }
            // FIXME: load a CRL.
            util::Thread::AddExitFunc (ExitFunc);
        }

        OpenSSLInit::~OpenSSLInit () {
            CRYPTO_set_dynlock_destroy_callback (0);
            CRYPTO_set_dynlock_lock_callback (0);
            CRYPTO_set_dynlock_create_callback (0);
            CRYPTO_set_id_callback (0);
            CRYPTO_set_locking_callback (0);
            staticLocks.deleteAndClear ();
            ERR_free_strings ();
            EVP_cleanup ();
            SystemCACertificates::Instance ().Flush ();
        }

        THEKOGANS_UTIL_IMPLEMENT_HEAP_WITH_LOCK (SessionInfo, util::SpinLock)

    #if defined (THEKOGANS_STREAM_HAVE_PUGIXML)
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
    #endif // defined (THEKOGANS_STREAM_HAVE_PUGIXML)

        SessionInfo SessionInfo::Empty;

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

    #if defined (THEKOGANS_STREAM_HAVE_PUGIXML)
        void SessionInfo::Parse (const pugi::xml_node &node) {
            serverName = util::Decodestring (node.attribute (ATTR_SERVER_NAME).value ());
            renegotiationFrequency = util::stringToui32 (node.attribute (ATTR_RENEGOTIATION_FREQUENCY).value ());
            bidirectionalShutdown = std::string (node.attribute (ATTR_BIDIRECTIONAL_SHUTDOWN).value ()) == util::XML_TRUE;
            countTransfered = util::stringToui32 (node.attribute (ATTR_COUNT_TRANSFERED).value ());
        }

        std::string SessionInfo::ToString (
                util::ui32 indentationLevel,
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
                        util::ui32Tostring (renegotiationFrequency)));
                attributes.push_back (
                    util::Attribute (
                        ATTR_BIDIRECTIONAL_SHUTDOWN,
                        bidirectionalShutdown ? util::XML_TRUE : util::XML_FALSE));
                attributes.push_back (
                    util::Attribute (
                        ATTR_COUNT_TRANSFERED,
                        util::ui32Tostring (countTransfered)));
                return util::OpenTag (indentationLevel, tagName, attributes, true, true);
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }
    #endif // defined (THEKOGANS_STREAM_HAVE_PUGIXML)

        _LIB_THEKOGANS_STREAM_DECL extern const char * const OPENSSL_TLS_1_0 = "1.0";
        _LIB_THEKOGANS_STREAM_DECL extern const char * const OPENSSL_TLS_1_1 = "1.1";
        _LIB_THEKOGANS_STREAM_DECL extern const char * const OPENSSL_TLS_1_2 = "1.2";

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

        _LIB_THEKOGANS_STREAM_DECL extern const char * const OPENSSL_DTLS_1_0 = "1.0";
        _LIB_THEKOGANS_STREAM_DECL extern const char * const OPENSSL_DTLS_1_2 = "1.2";

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
                return strcasecmp (serverName.c_str (), certificateName.c_str ()) == 0;
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
            X509Ptr cert (SSL_get_peer_certificate (ssl));
            return cert.get () != 0 &&
                (CheckSubjectName (cert.get (), serverName) ||
                    CheckSubjectAltName (cert.get (), serverName)) ?
                X509_V_OK : X509_V_ERR_APPLICATION_VERIFICATION;
        }

        _LIB_THEKOGANS_STREAM_DECL void _LIB_THEKOGANS_STREAM_API
        GetCRLDistributionPoints (
                X509 *cert,
                std::vector<std::string> &crlDistributionPoints) {
            STACK_OF (DIST_POINT) *distributionPoints =
                (STACK_OF (DIST_POINT) *)X509_get_ext_d2i (cert, NID_crl_distribution_points, 0, 0);
            for (int i = 0, count = sk_DIST_POINT_num (distributionPoints); i < count; ++i) {
                DIST_POINT_NAME *distributionPoint = sk_DIST_POINT_value (distributionPoints, i)->distpoint;
                if (distributionPoint->type == 0) {
                    for (int j = 0, count = sk_GENERAL_NAME_num (distributionPoint->name.fullname); j < count; ++j) {
                        ASN1_IA5STRING *url =
                            sk_GENERAL_NAME_value (distributionPoint->name.fullname, j)->d.uniformResourceIdentifier;
                        crlDistributionPoints.push_back (
                            std::string (
                                (const char *)ASN1_STRING_data (url),
                                ASN1_STRING_length (url)));
                    }
                }
                else if (distributionPoint->type == 1) {
                    STACK_OF (X509_NAME_ENTRY) *relativeNames = distributionPoint->name.relativename;
                    for (int j = 0, count = sk_X509_NAME_ENTRY_num (relativeNames); j < count; ++j) {
                        ASN1_STRING *url = X509_NAME_ENTRY_get_data (sk_X509_NAME_ENTRY_value (relativeNames, j));
                        crlDistributionPoints.push_back (
                            std::string(
                                (const char *)ASN1_STRING_data (url),
                                ASN1_STRING_length (url)));
                    }
                }
            }
        }

        _LIB_THEKOGANS_STREAM_DECL X509_CRLPtr _LIB_THEKOGANS_STREAM_API
        LoadCRL (
                const std::string &path,
                util::ui32 format,
                pem_password_cb *passwordCallback,
                void *userData) {
            if (!path.empty () && (format == FORMAT_DER || format == FORMAT_PEM)) {
                BIOPtr bio (BIO_new_file (path.c_str (), "r"));
                if (bio.get () != 0) {
                    X509_CRLPtr crl (format == FORMAT_DER ?
                        d2i_X509_CRL_bio (bio.get (), 0) :
                        PEM_read_bio_X509_CRL (bio.get (), 0, passwordCallback, userData));
                    if (crl.get () != 0) {
                        return crl;
                    }
                    else {
                        THEKOGANS_STREAM_THROW_OPENSSL_EXCEPTION;
                    }
                }
                else {
                    THEKOGANS_STREAM_THROW_OPENSSL_EXCEPTION;
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        _LIB_THEKOGANS_STREAM_DECL void _LIB_THEKOGANS_STREAM_API
        CacheSystemCACertificates (bool loadSystemRootCACertificatesOnly) {
            SystemCACertificates::Instance ().Load (loadSystemRootCACertificatesOnly);
        }

        _LIB_THEKOGANS_STREAM_DECL void _LIB_THEKOGANS_STREAM_API
        LoadSystemCACertificates (SSL_CTX *ctx) {
            if (ctx != 0) {
                SystemCACertificates::Instance ().Use (ctx);
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        _LIB_THEKOGANS_STREAM_DECL void _LIB_THEKOGANS_STREAM_API
        LoadCACertificates (
                SSL_CTX *ctx,
                const std::list<std::string> &caCertificates,
                pem_password_cb *passwordCallback,
                void *userData) {
            if (ctx != 0 && !caCertificates.empty ()) {
                X509_STOREPtr newStore;
                X509_STORE *store = SSL_CTX_get_cert_store (ctx);
                if (store == 0) {
                    newStore.reset (X509_STORE_new ());
                    if (newStore.get () != 0) {
                        store = newStore.get ();
                    }
                    else {
                        THEKOGANS_STREAM_THROW_OPENSSL_EXCEPTION;
                    }
                }
                for (std::list<std::string>::const_iterator
                        it = caCertificates.begin (),
                        end = caCertificates.end (); it != end; ++it) {
                    if (X509_STORE_add_cert (store,
                            ParsePEMCertificate ((*it).c_str (), (*it).size (),
                                passwordCallback, userData).get ()) != 1) {
                        THEKOGANS_STREAM_THROW_OPENSSL_EXCEPTION;
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
                        ParsePEMCertificate (&certificate[0], certificate.size (),
                            passwordCallback, userData).get ()) == 1) {
                    SSL_CTX_clear_chain_certs (ctx);
                    for (std::list<std::string>::const_iterator
                            end = certificateChain.end (); it != end; ++it) {
                        const std::string &certificate = *it;
                        if (SSL_CTX_add1_chain_cert (ctx,
                                ParsePEMCertificate (&certificate[0], certificate.size (),
                                    passwordCallback, userData).get ()) != 1) {
                            THEKOGANS_STREAM_THROW_OPENSSL_EXCEPTION;
                        }
                    }
                }
                else {
                    THEKOGANS_STREAM_THROW_OPENSSL_EXCEPTION;
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
                        ParsePrivateKey (&privateKey[0], privateKey.size (),
                            passwordCallback, userData).get ()) != 1) {
                    THEKOGANS_STREAM_THROW_OPENSSL_EXCEPTION;
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
                    THEKOGANS_STREAM_THROW_OPENSSL_EXCEPTION;
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
                            ParseDHParams (&dhParams[0], dhParams.size (),
                                passwordCallback, userData).get ()) != 1) {
                        THEKOGANS_STREAM_THROW_OPENSSL_EXCEPTION;
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
                    EC_KEYPtr ecdh (
                        EC_KEY_new_by_curve_name (OBJ_sn2nid (ecdhParams.c_str ())));
                    if (ecdh.get () == 0 || SSL_CTX_set_tmp_ecdh (ctx, ecdh.get ()) != 1) {
                        THEKOGANS_STREAM_THROW_OPENSSL_EXCEPTION;
                    }
                }
                else if (ecdhParamsType == "pem") {
                    EVP_PKEYPtr key = ParsePUBKEY (&ecdhParams[0],
                        ecdhParams.size (), passwordCallback, userData);
                    if (key.get () != 0) {
                        EC_KEYPtr ecdh (EVP_PKEY_get1_EC_KEY (key.get ()));
                        if (ecdh.get () == 0 || SSL_CTX_set_tmp_ecdh (ctx, ecdh.get ()) != 1) {
                            THEKOGANS_STREAM_THROW_OPENSSL_EXCEPTION;
                        }
                    }
                    else {
                        THEKOGANS_STREAM_THROW_OPENSSL_EXCEPTION;
                    }
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        _LIB_THEKOGANS_STREAM_DECL X509Ptr _LIB_THEKOGANS_STREAM_API
        ParseDERCertificate (
                const void *buffer,
                std::size_t length) {
            if (buffer != 0 && length > 0) {
                X509Ptr certificate (d2i_X509 (0, (const unsigned char **)&buffer, (long)length));
                if (certificate.get () != 0) {
                    return certificate;
                }
                else {
                    THEKOGANS_STREAM_THROW_OPENSSL_EXCEPTION;
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        _LIB_THEKOGANS_STREAM_DECL X509Ptr _LIB_THEKOGANS_STREAM_API
        ParsePEMCertificate (
                const void *buffer,
                std::size_t length,
                pem_password_cb *passwordCallback,
                void *userData) {
            if (buffer != 0 && length > 0) {
                // NOTE: I hate casting away constness, but thankfully,
                // in this case it's harmless. Even though BIO_new_mem_buf
                // wants an util::ui8 *, it marks the bio as read only,
                // and therefore will not alter the buffer.
                BIOPtr bio (BIO_new_mem_buf ((util::ui8 *)buffer, (int)length));
                if (bio.get () != 0) {
                    X509Ptr certificate (PEM_read_bio_X509 (bio.get (), 0, passwordCallback, userData));
                    if (certificate.get () != 0) {
                        return certificate;
                    }
                    else {
                        THEKOGANS_STREAM_THROW_OPENSSL_EXCEPTION;
                    }
                }
                else {
                    THEKOGANS_STREAM_THROW_OPENSSL_EXCEPTION;
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        _LIB_THEKOGANS_STREAM_DECL EVP_PKEYPtr _LIB_THEKOGANS_STREAM_API
        ParsePUBKEY (
                const void *buffer,
                std::size_t length,
                pem_password_cb *passwordCallback,
                void *userData) {
            if (buffer != 0 && length > 0) {
                // NOTE: I hate casting away constness, but thankfully,
                // in this case it's harmless. Even though BIO_new_mem_buf
                // wants an util::ui8 *, it marks the bio as read only,
                // and therefore will not alter the buffer.
                BIOPtr bio (BIO_new_mem_buf ((util::ui8 *)buffer, (int)length));
                if (bio.get () != 0) {
                    EVP_PKEYPtr key (PEM_read_bio_PUBKEY (bio.get (), 0, passwordCallback, userData));
                    if (key.get () != 0) {
                        return key;
                    }
                    else {
                        THEKOGANS_STREAM_THROW_OPENSSL_EXCEPTION;
                    }
                }
                else {
                    THEKOGANS_STREAM_THROW_OPENSSL_EXCEPTION;
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        _LIB_THEKOGANS_STREAM_DECL EVP_PKEYPtr _LIB_THEKOGANS_STREAM_API
        ParsePrivateKey (
                const void *buffer,
                std::size_t length,
                pem_password_cb *passwordCallback,
                void *userData) {
            if (buffer != 0 && length > 0) {
                // NOTE: I hate casting away constness, but thankfully,
                // in this case it's harmless. Even though BIO_new_mem_buf
                // wants an util::ui8 *, it marks the bio as read only,
                // and therefore will not alter the buffer.
                BIOPtr bio (BIO_new_mem_buf ((util::ui8 *)buffer, (int)length));
                if (bio.get () != 0) {
                    EVP_PKEYPtr key (PEM_read_bio_PrivateKey (bio.get (), 0, passwordCallback, userData));
                    if (key.get () != 0) {
                        return key;
                    }
                    else {
                        THEKOGANS_STREAM_THROW_OPENSSL_EXCEPTION;
                    }
                }
                else {
                    THEKOGANS_STREAM_THROW_OPENSSL_EXCEPTION;
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        _LIB_THEKOGANS_STREAM_DECL DHPtr _LIB_THEKOGANS_STREAM_API
        ParseDHParams (
                const void *buffer,
                std::size_t length,
                pem_password_cb *passwordCallback,
                void *userData) {
            if (buffer != 0 && length > 0) {
                // NOTE: I hate casting away constness, but thankfully,
                // in this case it's harmless. Even though BIO_new_mem_buf
                // wants an util::ui8 *, it marks the bio as read only,
                // and therefore will not alter the buffer.
                BIOPtr bio (BIO_new_mem_buf ((util::ui8 *)buffer, (int)length));
                if (bio.get () != 0) {
                    DHPtr dh (PEM_read_bio_DHparams (bio.get (), 0, passwordCallback, userData));
                    if (dh.get () != 0) {
                        return dh;
                    }
                    else {
                        THEKOGANS_STREAM_THROW_OPENSSL_EXCEPTION;
                    }
                }
                else {
                    THEKOGANS_STREAM_THROW_OPENSSL_EXCEPTION;
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        _LIB_THEKOGANS_STREAM_DECL DSAPtr _LIB_THEKOGANS_STREAM_API
        ParseDSAParams (
                const void *buffer,
                std::size_t length,
                pem_password_cb *passwordCallback,
                void *userData) {
            if (buffer != 0 && length > 0) {
                // NOTE: I hate casting away constness, but thankfully,
                // in this case it's harmless. Even though BIO_new_mem_buf
                // wants an util::ui8 *, it marks the bio as read only,
                // and therefore will not alter the buffer.
                BIOPtr bio (BIO_new_mem_buf ((util::ui8 *)buffer, (int)length));
                if (bio.get () != 0) {
                    DSAPtr dsa (PEM_read_bio_DSAparams (bio.get (), 0, passwordCallback, userData));
                    if (dsa.get () != 0) {
                        return dsa;
                    }
                    else {
                        THEKOGANS_STREAM_THROW_OPENSSL_EXCEPTION;
                    }
                }
                else {
                    THEKOGANS_STREAM_THROW_OPENSSL_EXCEPTION;
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        //EVP_PKEY *publicKey = X509_get_pubkey (issuer);
        //if (publicKey != 0 && X509_CRL_verify (crl, publicKey)) {
        _LIB_THEKOGANS_STREAM_DECL bool _LIB_THEKOGANS_STREAM_API
        CheckCRL (
                X509 *cert,
                X509_CRL *crl) {
            if (cert != 0 && crl != 0) {
                ASN1_INTEGER *serial = X509_get_serialNumber (cert);
                STACK_OF (X509_REVOKED) *revoked = crl->crl->revoked;
                for (int i = 0, count = sk_X509_REVOKED_num (revoked); i < count; ++i) {
                    X509_REVOKED *entry = sk_X509_REVOKED_value (revoked, i);
                    if (entry->serialNumber->length == serial->length &&
                            memcmp (entry->serialNumber->data, serial->data, serial->length) == 0) {
                        return true;
                    }
                }
                return false;
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        _LIB_THEKOGANS_STREAM_DECL util::Exception _LIB_THEKOGANS_STREAM_API
        CreateOpenSSLException (
                const char *file,
                const char *function,
                util::ui32 line,
                const char *buildTime,
                const char *message) {
            THEKOGANS_UTIL_ERROR_CODE errorCode = ERR_get_error ();
            char buffer[256];
            ERR_error_string_n (errorCode, buffer, sizeof (buffer));
            util::Exception exception (file, function, line, buildTime,
                errorCode, util::FormatString ("[0x%x:%d - %s]%s",
                    errorCode, errorCode, buffer, message));
            while ((errorCode = ERR_get_error_line (&file, (int *)&line)) != 0) {
                exception.NoteLocation (file, "", line, "");
            }
            return exception;
        }

    } // namespace stream
} // namespace thekogans

#endif // defined (THEKOGANS_STREAM_HAVE_OPENSSL)
