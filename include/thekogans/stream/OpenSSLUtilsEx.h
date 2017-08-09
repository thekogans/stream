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

#if !defined (__thekogans_stream_OpenSSLUtilsEx_h)
#define __thekogans_stream_OpenSSLUtilsEx_h

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
#include <openssl/aes.h>
#include "thekogans/stream/OpenSSLUtils.h"

namespace thekogans {
    namespace stream {

        /// \struct EVP_PKEY_CTXDeleter OpenSSLUtils.h thekogans/stream/OpenSSLUtils.h
        ///
        /// \brief
        /// Custom deleter for EVP_PKEY_CTX.
        struct _LIB_THEKOGANS_STREAM_DECL EVP_PKEY_CTXDeleter {
            /// \brief
            /// Called by unique_ptr::~unique_ptr.
            /// \param[in] ctx EVP_PKEY_CTX to delete.
            void operator () (EVP_PKEY_CTX *ctx);
        };
        /// \brief
        /// Convenient typedef for std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTXDeleter>.
        typedef std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTXDeleter> EVP_PKEY_CTXPtr;

        /// \struct EC_POINTDeleter OpenSSLUtils.h thekogans/stream/OpenSSLUtils.h
        ///
        /// \brief
        /// Custom deleter for EC_POINT.
        struct _LIB_THEKOGANS_STREAM_DECL EC_POINTDeleter {
            /// \brief
            /// Called by unique_ptr::~unique_ptr.
            /// \param[in] point EC_POINT to delete.
            void operator () (EC_POINT *point);
        };
        /// \brief
        /// Convenient typedef for std::unique_ptr<EC_POINT, EC_POINTDeleter>.
        typedef std::unique_ptr<EC_POINT, EC_POINTDeleter> EC_POINTPtr;

        /// \struct EVP_CIPHER_CTXDeleter OpenSSLUtils.h thekogans/stream/OpenSSLUtils.h
        ///
        /// \brief
        /// Custom deleter for EVP_CIPHER_CTX.
        struct _LIB_THEKOGANS_STREAM_DECL EVP_CIPHER_CTXDeleter {
            /// \brief
            /// Called by unique_ptr::~unique_ptr.
            /// \param[in] key EVP_CIPHER_CTX to delete.
            void operator () (EVP_CIPHER_CTX *ctx);
        };
        /// \brief
        /// Convenient typedef for std::unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTXDeleter>.
        typedef std::unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTXDeleter> EVP_CIPHER_CTXPtr;

        /// \struct EVP_MD_CTXDeleter OpenSSLUtils.h thekogans/stream/OpenSSLUtils.h
        ///
        /// \brief
        /// Custom deleter for EVP_MD_CTX.
        struct _LIB_THEKOGANS_STREAM_DECL EVP_MD_CTXDeleter {
            /// \brief
            /// Called by unique_ptr::~unique_ptr.
            /// \param[in] key EVP_MD_CTX to delete.
            void operator () (EVP_MD_CTX *ctx);
        };
        /// \brief
        /// Convenient typedef for std::unique_ptr<EVP_MD_CTX, EVP_MD_CTXDeleter>.
        typedef std::unique_ptr<EVP_MD_CTX, EVP_MD_CTXDeleter> EVP_MD_CTXPtr;

        /// \struct BIGNUMDeleter OpenSSLUtils.h thekogans/stream/OpenSSLUtils.h
        ///
        /// \brief
        /// Custom deleter for BIGNUM.
        struct _LIB_THEKOGANS_STREAM_DECL BIGNUMDeleter {
            /// \brief
            /// Called by unique_ptr::~unique_ptr.
            /// \param[in] key BIGNUM to delete.
            void operator () (BIGNUM *bn);
        };
        /// \brief
        /// Convenient typedef for std::unique_ptr<BIGNUM, BIGNUMDeleter>.
        typedef std::unique_ptr<BIGNUM, BIGNUMDeleter> BIGNUMPtr;

        /// \brief
        /// The following utilities aid in performing basic crypto operations outside of TLS.
        /// Support for [EC]DH shared secret negotiation, symmetric key generation, buffer
        /// encryption and decryption, public key generation and buffer signing and signature
        /// verification is provided.

        /// \struct SharedSecret OpenSSLUtils.h thekogans/stream/OpenSSLUtils.h
        ///
        /// \brief
        /// An abstract base class for computing shared secrets.
        struct _LIB_THEKOGANS_STREAM_DECL SharedSecret {
            /// \brief
            /// Convenient typedef for std::unique_ptr<SharedSecret>.
            typedef std::unique_ptr<SharedSecret> UniquePtr;

            /// \brief
            /// dtor.
            virtual ~SharedSecret () {}

            /// \brief
            /// GetPublicKey is designed to return the same public key every time
            /// it's called. Call Reset if you want to generate a new public key
            /// next time you call GetPublicKey.
            virtual void Reset () = 0;

            /// \brief
            /// Call this method to get the public key (your half of the shared secret).
            /// \return The public key.
            virtual util::Buffer::UniquePtr GetPublicKey () = 0;
            /// \brief
            /// Call this method after you've received the peer's public key to finish
            /// computing the shared secret.
            /// \param[in] publicKey Peers public key.
            /// \return The shared secret.
            virtual util::SecureBuffer::UniquePtr ComputeSharedSecret (
                const util::Buffer &publicKey) = 0;
        };

        /// \brief
        /// ****************************** VERY IMPORTANT ******************************
        /// When using \see{DHSharedSecret} and \see{ECDHSharedSecret} please note that
        /// the shared secret generated does not have the necessary properties to make
        /// it ideal for cryptographic key derivation. Specifically, the shared secret
        /// derived in this way may not be evenly distributed within the key space. You
        /// are therefore very strongly encouraged to pass the shared secret (possibly
        /// combining it with other data first) through a message digest (\see{util::SHA2}
        /// is a very good choice).
        /// NOTE: If you're planning on creating \see{SymmetricKey} objects with your
        /// shared secret there's nothing for you to do as internally it calls EVP_BytesToKey
        /// which does the right thing.
        /// ****************************************************************************

        /// \struct DHSharedSecret OpenSSLUtils.h thekogans/stream/OpenSSLUtils.h
        ///
        /// \brief
        /// Use this class to compute a Diffie-Hellman (DH) shared secret. This computation is
        /// a two step process. After creating an instance of this class call GetPublicKey to
        /// get the public key. Send this public key to your peer and wait for the reply.
        /// After getting the peer's public key, call ComputeSharedSecret to compute the shared
        /// secret.
        struct _LIB_THEKOGANS_STREAM_DECL DHSharedSecret : public SharedSecret {
            /// \brief
            /// Primes used for Diffie-Hellman key exchange.
            /// NOTE: These came out of https://tools.ietf.org/html/rfc3526.
            enum Prime {
                PRIME_MODP_1536,
                PRIME_MODP_2048,
                PRIME_MODP_3072,
                PRIME_MODP_4096,
                PRIME_MODP_6144,
                PRIME_MODP_8192
            };

        private:
            /// \brief
            /// A prime suitable for DH key exchange.
            Prime prime;
            /// \brief
            /// Diffie-Hellman parameters.
            DHPtr dh;

        public:
            /// \brief
            /// ctor.
            /// \param[in] prime A prime suitable for DH key exchange.
            /// VERY IMPORTANT: Computing primes suitable for key exchange
            /// is very difficult. You are strongly encouraged to use one
            /// of the primes provided above.
            DHSharedSecret (Prime prime_ = PRIME_MODP_8192);

            /// \brief
            /// GetPublicKey is designed to return the same public key every time
            /// it's called. Call Reset if you want to generate a new public key
            /// next time you call GetPublicKey.
            virtual void Reset ();

            /// \brief
            /// Call this method to get the public key (your half of the shared secret).
            /// \return The public key.
            virtual util::Buffer::UniquePtr GetPublicKey ();
            /// \brief
            /// Call this method after you've received the peer's public key to finish
            /// computing the shared secret.
            /// \param[in] publicKey Peers public key.
            /// \return The shared secret.
            virtual util::SecureBuffer::UniquePtr ComputeSharedSecret (
                const util::Buffer &publicKey);

            /// \brief
            /// DHSharedSecret is neither copy constructable, nor assignable.
            THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (DHSharedSecret)
        };

        /// \struct ECDHSharedSecret OpenSSLUtils.h thekogans/stream/OpenSSLUtils.h
        ///
        /// \brief
        /// Use this class to compute an Elliptic Curve Diffie-Hellman (ECDH) shared secret.
        /// This computation is a two step process. After creating an instance of this class
        /// call GetPublicKey to get the public key. Send this public key to your peer and
        /// wait for the reply. After getting the peer's public key, call ComputeSharedSecret
        /// to compute the shared secret.
        struct _LIB_THEKOGANS_STREAM_DECL ECDHSharedSecret : public SharedSecret {
        private:
            /// \brief
            /// An elliptic curve id to use for key generation.
            int nid;
            /// \brief
            /// Elliptic curve Diffie-Hellman key.
            EC_KEYPtr key;

        public:
            /// \brief
            /// ctor.
            /// \param[in] nid An elliptic curve id to use for key generation.
            ECDHSharedSecret (int nid_ = NID_X9_62_prime256v1);

            /// \brief
            /// GetPublicKey is designed to return the same public key every time
            /// it's called. Call Reset if you want to generate a new public key
            /// next time you call GetPublicKey.
            virtual void Reset ();

            /// \brief
            /// Call this method to get the public key (your half of the shared secret).
            /// \return The public key.
            virtual util::Buffer::UniquePtr GetPublicKey ();
            /// \brief
            /// Call this method after you've received the peer's public key to finish
            /// computing the shared secret.
            /// \param[in] publicKey Peers public key.
            /// \return The shared secret.
            virtual util::SecureBuffer::UniquePtr ComputeSharedSecret (
                const util::Buffer &publicKey);

            /// \brief
            /// ECDHSharedSecret is neither copy constructable, nor assignable.
            THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (ECDHSharedSecret)
        };

        /// \struct SymmetricKey OpenSSLUtils.h thekogans/stream/OpenSSLUtils.h
        ///
        /// \brief
        /// Generate a symmetric key suitable for encrypting and decryptiing buffers.
        struct _LIB_THEKOGANS_STREAM_DECL SymmetricKey {
            /// \brief
            /// Convenient typedef for std::unique_ptr<SymmetricKey>.
            typedef std::unique_ptr<SymmetricKey> UniquePtr;

            /// \brief
            /// SymmetricKey has a private heap to help with memory
            /// management, performance, and global heap fragmentation.
            THEKOGANS_UTIL_DECLARE_HEAP_WITH_LOCK (SymmetricKey, util::SpinLock)

            /// \brief
            /// Cipher to use for encryption/decryption.
            const EVP_CIPHER *cipher;
            /// \brief
            /// Message digest to use for encryption/decryption.
            const EVP_MD *md;
            /// \brief
            /// Key.
            util::SecureBuffer key;
            /// \brief
            /// IV.
            util::SecureBuffer iv;

            /// \brief
            /// ctor.
            /// \param[in] secret Secret to derive key and iv.
            /// NOTE: This can be a password or a shared secret derived from
            /// \see{DHSharedSecret} or \see{ECDHSharedSecret}.
            /// \param[in] secretLength Secret length.
            /// \param[in] salt An optional 8 byte buffer containg salt.
            /// \param[in] cipher_ Cipher to use for encryption/decryption.
            /// \param[in] md_ Message digest to use for encryption/decryption.
            SymmetricKey (
                const void *secret,
                std::size_t secretLength,
                const void *salt = 0,
                const EVP_CIPHER *cipher_ = 0 /*EVP_aes_256_cbc ()*/,
                const EVP_MD *md_ = 0 /*EVP_sha256 ()*/);

            /// \brief
            /// SymmetricKey is neither copy constructable, nor assignable.
            THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (SymmetricKey)
        };

        /// \struct Encryptor OpenSSLUtils.h thekogans/stream/OpenSSLUtils.h
        ///
        /// \brief
        /// Uses OpenSSL EVP library to encrypt a byte stream.
        struct _LIB_THEKOGANS_STREAM_DECL Encryptor {
        private:
            /// \brief
            /// Cipher context used during encryption.
            EVP_CIPHER_CTXPtr ctx;
            /// \brief
            /// Cipher text generated by the encryptor.
            util::Buffer::UniquePtr ciphertext;

        public:
            /// \brief
            /// ctor.
            Encryptor ();

            /// \brief
            /// Initialize the encryptor.
            /// \param[in] encryptionKey Key used to encrypt the buffer.
            /// \param[in] endianness Cipher text buffer endianness.
            /// \param[in] engine OpenSSL engine object.
            void Init (
                const SymmetricKey &encryptionKey,
                util::Endianness endianness = util::HostEndian,
                ENGINE *engine = 0);
            /// \brief
            /// Encrypt a given buffer.
            /// \param[in] buffer Buffer to encrypt.
            /// \param[in] length Length of buffer.
            void Update (
                const void *buffer,
                std::size_t length);
            /// \brief
            /// Finish encrypting and return the encrypted buffer.
            /// \return Encrypted buffer.
            util::Buffer::UniquePtr Final ();

            /// \brief
            /// Encryptor is neither copy constructable, nor assignable.
            THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (Encryptor)
        };

        /// \struct Decryptor OpenSSLUtils.h thekogans/stream/OpenSSLUtils.h
        ///
        /// \brief
        /// Uses OpenSSL EVP library to decrypt a byte stream.
        struct _LIB_THEKOGANS_STREAM_DECL Decryptor {
        private:
            /// \brief
            /// Cipher context used during decryption.
            EVP_CIPHER_CTXPtr ctx;
            /// \brief
            /// Plain text generated by the decryptor.
            util::Buffer::UniquePtr plaintext;

        public:
            /// \brief
            /// ctor.
            Decryptor ();

            /// \brief
            /// Initialize the decryptor.
            /// \param[in] decryptionKey Key used to decrypt the buffer.
            /// \param[in] endianness Plain text buffer endianness.
            /// \param[in] engine OpenSSL engine object.
            void Init (
                const SymmetricKey &decryptionKey,
                util::Endianness endianness = util::HostEndian,
                ENGINE *engine = 0);
            /// \brief
            /// Decrypt the givven buffer.
            /// \param[in] buffer Buffer to decrypt.
            /// \param[in] length Length of buffer.
            void Update (
                const void *buffer,
                std::size_t length);
            /// \brief
            /// Finish decrypting and return the decrypted buffer.
            /// \return Decrypted buffer.
            util::Buffer::UniquePtr Final ();

            /// \brief
            /// Decryptor is neither copy constructable, nor assignable.
            THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (Decryptor)
        };

        /// \brief
        /// Create a BIGNUMPtr and initialize it to a given value.
        /// \param[in] value Value to initialize the BIGNUM to.
        /// \return BIGNUMPtr initialized to a given value.
        _LIB_THEKOGANS_STREAM_DECL BIGNUMPtr _LIB_THEKOGANS_STREAM_API
            BIGNUMFromui32 (util::ui32 value);

        /// \brief
        /// Return a DER encoded public key portion of the given public/private key.
        /// \param[in] key Public/private key whose public key to return.
        /// \return A DER encoded public key portion of the given public/private key.
        _LIB_THEKOGANS_STREAM_DECL util::Buffer::UniquePtr _LIB_THEKOGANS_STREAM_API
            GetPublicKey (EVP_PKEY &key);
        /// \brief
        /// Return a DER encoded private key.
        /// \param[in] key Private key to encode.
        /// \return A DER encoded private key.
        _LIB_THEKOGANS_STREAM_DECL util::Buffer::UniquePtr _LIB_THEKOGANS_STREAM_API
            GetPrivateKey (EVP_PKEY &key);
        /// \brief
        /// Convert a DER encoding in to a public key.
        /// \param[in] publicKey DER encoded public key.
        /// \param[in] publicKeyLength Public key length.
        /// \return Decoded public key.
        _LIB_THEKOGANS_STREAM_DECL EVP_PKEYPtr _LIB_THEKOGANS_STREAM_API
            CreatePublicKey (
                const void *publicKey,
                std::size_t publicKeyLength);
        /// \brief
        /// Convert a DER encoding in to a private key.
        /// \param[in] privateKey DER encoded private key.
        /// \param[in] privateKeyLength Private key length.
        /// \return Decoded private key.
        _LIB_THEKOGANS_STREAM_DECL EVP_PKEYPtr _LIB_THEKOGANS_STREAM_API
            CreatePrivateKey (
                const void *privateKey,
                std::size_t privateKeyLength);
        /// \brief
        /// Create an RSA key.
        /// \param[in] bits The length of the key.
        /// \param[in] publicExponent RSA key public exponent.
        /// \param[in] engine OpenSSL engine object.
        /// \return A new RSA key.
        _LIB_THEKOGANS_STREAM_DECL EVP_PKEYPtr _LIB_THEKOGANS_STREAM_API
            CreateRSAKey (
                std::size_t bits,
                BIGNUMPtr publicExponent = BIGNUMFromui32 (65537),
                ENGINE *engine = 0);
        /// \brief
        /// Create an DSA key.
        /// \param[in] bits The length of the key.
        /// \param[in] engine OpenSSL engine object.
        /// \return A new DSA key.
        _LIB_THEKOGANS_STREAM_DECL EVP_PKEYPtr _LIB_THEKOGANS_STREAM_API
            CreateDSAKey (
                std::size_t bits,
                ENGINE *engine = 0);
        /// \brief
        /// Create an DH key.
        /// \param[in] primeLength The length of the prime (in bits).
        /// \param[in] generator DH key generator.
        /// \param[in] engine OpenSSL engine object.
        /// \return A new DH key.
        _LIB_THEKOGANS_STREAM_DECL EVP_PKEYPtr _LIB_THEKOGANS_STREAM_API
            CreateDHKey (
                std::size_t primeLength,
                std::size_t generator = 2,
                ENGINE *engine = 0);
        /// \brief
        /// Create an EC key.
        /// \param[in] nid Elliptic curve object id.
        /// \param[in] parameterEncoding How to encode curve parameters
        /// (OPENSSL_EC_EXPLICIT_CURVE | OPENSSL_EC_NAMED_CURVE).
        /// \param[in] engine OpenSSL engine object.
        /// \return A new EC key.
        _LIB_THEKOGANS_STREAM_DECL EVP_PKEYPtr _LIB_THEKOGANS_STREAM_API
            CreateECKey (
                int nid = NID_X9_62_prime256v1,
                int parameterEncoding = 0,
                ENGINE *engine = 0);
        /// \brief
        /// Create an HMAC key.
        /// \param[in] secret Secret to derive key.
        /// NOTE: This can be a password or a shared secret derived from
        /// \see{DHSharedSecret} or \see{ECDHSharedSecret}.
        /// \param[in] secretLength Secret length.
        /// \param[in] engine OpenSSL engine object.
        /// \return A new HMAC key.
        _LIB_THEKOGANS_STREAM_DECL EVP_PKEYPtr _LIB_THEKOGANS_STREAM_API
            CreateHMACKey (
                const void *secret,
                std::size_t secretLength,
                ENGINE *engine = 0);
        /// \brief
        /// Create an CMAC key.
        /// \param[in] password Secret to derive key.
        /// NOTE: This can be a password or a shared secret derived from
        /// \see{DHSharedSecret} or \see{ECDHSharedSecret}.
        /// \param[in] secretLength Secret length.
        /// \param[in] cipher Cipher to use for encryption/decryption.
        /// \param[in] engine OpenSSL engine object.
        /// \return A new CMAC key.
        _LIB_THEKOGANS_STREAM_DECL EVP_PKEYPtr _LIB_THEKOGANS_STREAM_API
            CreateCMACKey (
                const void *secret,
                std::size_t secretLength,
                const EVP_CIPHER *cipher = 0 /*EVP_aes_256_cbc ()*/,
                ENGINE *engine = 0);

        /// \brief
        /// Create a buffer signature. Key can be any supported OpenSSL key type.
        /// \param[in] buffer Buffer whose signature to create.
        /// \param[in] length Buffer length.
        /// \param[in] privateKey Private key used to sign the digest.
        /// \param[in] md Message digest.
        /// \param[in] endianness Signature buffer endianness.
        /// \param[in] engine OpenSSL engine object.
        /// \return Buffer signature.
        _LIB_THEKOGANS_STREAM_DECL util::Buffer::UniquePtr _LIB_THEKOGANS_STREAM_API
            SignBuffer (
                const void *buffer,
                std::size_t length,
                EVP_PKEY &privateKey,
                const EVP_MD *md = 0 /*EVP_sha256 ()*/,
                util::Endianness endianness = util::NetworkEndian,
                ENGINE *engine = 0);
        /// \brief
        /// Encrypt the given buffer.
        /// \param[in] buffer Buffer to encrypt.
        /// \param[in] length Buffer length.
        /// \param[in] encryptionKey Symmetric key used to encrypt buffer.
        /// \param[in] endianness Cipher text buffer endianness.
        /// \param[in] engine OpenSSL engine object.
        /// \return Encrypted buffer.
        _LIB_THEKOGANS_STREAM_DECL util::Buffer::UniquePtr _LIB_THEKOGANS_STREAM_API
            EncryptBuffer (
                const void *buffer,
                std::size_t length,
                const SymmetricKey &encryptionKey,
                util::Endianness endianness = util::NetworkEndian,
                ENGINE *engine = 0);
        /// \brief
        /// Sign and encrypt the given buffer.
        /// \param[in] buffer Buffer to encrypt.
        /// \param[in] length Buffer length.
        /// \param[in] encryptionKey Symmetric key used to encrypt buffer.
        /// \param[in] signatureKey Private key used to sign the digest.
        /// \param[in] md Message digest.
        /// \param[in] endianness Cipher text buffer endianness.
        /// \param[in] engine OpenSSL engine object.
        /// \return Signed and encrypted buffer.
        _LIB_THEKOGANS_STREAM_DECL util::Buffer::UniquePtr _LIB_THEKOGANS_STREAM_API
            SignAndEncryptBuffer (
                const void *buffer,
                std::size_t length,
                const SymmetricKey &encryptionKey,
                EVP_PKEY &signatureKey,
                const EVP_MD *md = 0 /*EVP_sha256 ()*/,
                util::Endianness endianness = util::NetworkEndian,
                ENGINE *engine = 0);
        /// \brief
        /// Decrypt the given buffer.
        /// \param[in] buffer Buffer to decrypt.
        /// \param[in] length Buffer length.
        /// \param[in] decryptionKey Symmetric key used to decrypt buffer.
        /// \param[in] endianness Plain text buffer endianness.
        /// \param[in] engine OpenSSL engine object.
        /// \return Decrypted buffer.
        _LIB_THEKOGANS_STREAM_DECL util::Buffer::UniquePtr _LIB_THEKOGANS_STREAM_API
            DecryptBuffer (
                const void *buffer,
                std::size_t length,
                const SymmetricKey &decryptionKey,
                util::Endianness endianness = util::NetworkEndian,
                ENGINE *engine = 0);
        /// \brief
        /// Verify a buffer signature. Key can be any supported OpenSSL key type.
        /// \param[in] buffer Buffer whose signature to verify.
        /// \param[in] bufferLength Buffer length.
        /// \param[in] signature Signature to verify.
        /// \param[in] signatureLength Signature length.
        /// \param[in] publicKey Public key used to verify the digest signature.
        /// \param[in] md Message digest.
        /// \param[in] engine OpenSSL engine object.
        /// \return true == valid, false == invalid.
        _LIB_THEKOGANS_STREAM_DECL bool _LIB_THEKOGANS_STREAM_API
            VerifyBufferSignature (
                const void *buffer,
                std::size_t bufferLength,
                const void *signature,
                std::size_t signatureLength,
                EVP_PKEY &publicKey,
                const EVP_MD *md = 0 /*EVP_sha256 ()*/,
                ENGINE *engine = 0);
        /// \brief
        /// Decrypt the given buffer and verify it's signature.
        /// \param[in] buffer Buffer to decrypt and verify.
        /// \param[in] length Buffer length.
        /// \param[in] decryptionKey Symmetric key used to decrypt buffer.
        /// \param[in] signatureKey Public key used to verify the digest signature.
        /// \param[in] md Message digest.
        /// \param[in] endianness Plain text buffer endianness.
        /// \param[in] engine OpenSSL engine object.
        /// \return Plain text buffer.
        _LIB_THEKOGANS_STREAM_DECL util::Buffer::UniquePtr _LIB_THEKOGANS_STREAM_API
            DecryptAndVerifyBufferSignature (
                const void *buffer,
                std::size_t length,
                const SymmetricKey &decryptionKey,
                EVP_PKEY &signatureKey,
                const EVP_MD *md = 0 /*EVP_sha256 ()*/,
                util::Endianness endianness = util::NetworkEndian,
                ENGINE *engine = 0);

        /// \brief
        /// General purpose One Time Password generator.
        /// \param[in] key Key to use with HMAC.
        /// \param[in] keyLength Key length.
        /// \param[in] buffer Data to hash.
        /// \param[in] bufferLength Buffer length.
        /// \param[in] md Message digest.
        /// \return One Time Password.
        /// NOTE: All passwords returned by OTP are six digits long.
        _LIB_THEKOGANS_STREAM_DECL std::string _LIB_THEKOGANS_STREAM_API OTP (
            const void *key,
            std::size_t keyLength,
            const void *buffer,
            std::size_t bufferLength,
            const EVP_MD *md = 0 /*EVP_sha1 ()*/);
        /// \brief
        /// [H | T] One Time Password generator. By default, uses
        /// the current time (TOTP) with a 30 second validity window.
        /// Pass a monotonically increasing counter to perform HOTP
        /// described in RFC 4226.
        /// \param[in] key Key to use with HMAC.
        /// \param[in] keyLength Key length.
        /// \param[in] value Value to hash.
        /// \param[in] md Message digest.
        /// \return One Time Password.
        _LIB_THEKOGANS_STREAM_DECL std::string _LIB_THEKOGANS_STREAM_API OTP (
            const void *key,
            std::size_t keyLength,
            util::ui64 value = time (0) / 30,
            const EVP_MD *md = 0 /*EVP_sha1 ()*/);

        /// \struct Decryptor OpenSSLUtils.h thekogans/stream/OpenSSLUtils.h
        ///
        /// \brief
        /// A KeySet contains a symmetric key and a signature key used by
        /// \see{SignAndEncryptBuffer} and \see{DecryptAndVerifyBufferSignature}.
        /// It also contains a \see{SharedSecret} object allowing for key exchange.
        struct _LIB_THEKOGANS_STREAM_DECL KeySet : public util::ThreadSafeRefCounted {
            /// \brief
            /// Convenient typedef for util::ThreadSafeRefCounted::Ptr<Stream>.
            typedef util::ThreadSafeRefCounted::Ptr<KeySet> Ptr;

            /// \brief
            /// Key set id.
            const util::ui32 id;
            /// \brief
            /// Used to perform a shared secret exchange.
            SharedSecret::UniquePtr sharedSecret;
            /// \brief
            /// Key used to encrypt/decrypt.
            SymmetricKey::UniquePtr encryptionKey;
            /// \brief
            /// Key used to sign/verify.
            EVP_PKEYPtr signatureKey;
            /// \brief
            /// Keeps track of the number of bytes used to encrypt/decrypt
            /// with this key set.
            THEKOGANS_UTIL_ATOMIC<util::ui32> byteCount;

            /// \brief
            /// ctor.
            /// \param[in] id_ Key set id.
            /// \param[in] sharedSecret_ Used to perform a shared secret exchange.
            KeySet (
                util::ui32 id_,
                SharedSecret::UniquePtr sharedSecret_ =
                    SharedSecret::UniquePtr (new DHSharedSecret)) :
                id (id_),
                sharedSecret (std::move (sharedSecret_)),
                byteCount (0) {}

            /// \brief
            /// Compute the keys using the given public key.
            /// \param[in] publicKey Public key used to compute the keys.
            void ComputeKeys (const util::Buffer &publicKey);

            /// \brief
            /// KeySet is neither copy constructable, nor assignable.
            THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (KeySet)
        };

    } // namespace stream
} // namespace thekogans

#endif // defined (THEKOGANS_STREAM_HAVE_OPENSSL)

#endif // !defined (__thekogans_stream_OpenSSLUtilsEx_h)
