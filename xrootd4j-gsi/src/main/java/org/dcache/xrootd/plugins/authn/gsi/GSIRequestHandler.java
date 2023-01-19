/**
 * Copyright (C) 2011-2023 dCache.org <support@dcache.org>
 * 
 * This file is part of xrootd4j.
 * 
 * xrootd4j is free software: you can redistribute it and/or modify it under the terms of the GNU
 * Lesser General Public License as published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 * 
 * xrootd4j is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License along with xrootd4j.  If
 * not, see http://www.gnu.org/licenses/.
 */
package org.dcache.xrootd.plugins.authn.gsi;

import static eu.emi.security.authn.x509.impl.CertificateUtils.Encoding.PEM;
import static io.netty.buffer.Unpooled.wrappedBuffer;
import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_DecryptErr;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_error;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType.kXRS_cipher;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType.kXRS_main;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType.kXRS_puk;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType.kXRS_rtag;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType.kXRS_signed_rtag;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType.kXRS_x509;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType.kXRS_x509_req;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.kGSErrBadRndmTag;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.kGSErrCreateBucket;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.kGSErrDecodeBuffer;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.kGSErrError;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.kXGC_cert;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.kXGC_sigpxy;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.kXGS_pxyreq;

import eu.emi.security.authn.x509.impl.CertificateUtils;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.PooledByteBufAllocator;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.dcache.xrootd.core.XrootdException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Shared settings and functionality for processing both client and server
 * GSI authentication requests.
 */
public abstract class GSIRequestHandler {

    protected static Logger LOGGER
          = LoggerFactory.getLogger(GSIRequestHandler.class);

    public static final String PROTOCOL = "gsi";

    public static final int PROTO_WITH_DELEGATION = 10400;
    public static final int PROTO_PRE_DELEGATION = 10300;
    public static final int PROTOCOL_VERSION = PROTO_WITH_DELEGATION;

    public static final String CRYPTO_MODE = "ssl";
    public static final String CRYPTO_MODE_NO_PAD = "sslnopad";

    /**
     * we limit ourselves to AES-128 with CBC blockmode.
     */
    public static final String SUPPORTED_CIPHER_ALGORITHM = "aes-128-cbc";

    public static final String SUPPORTED_DIGESTS = "sha1:md5";

    /**
     * RSA algorithm, no block chaining mode (not a block-cipher) and PKCS1
     * padding, which is recommended to be used in conjunction with RSA
     */
    public static final String ASYNC_CIPHER_MODE = "RSA/NONE/PKCS1Padding";

    /**
     * Sync cipher mode supported by the server. It currently must match the
     * SUPPORTED_CIPHER_ALGORITHM advertised by the server
     */
    public static final String SYNC_CIPHER_MODE_PADDED = "AES/CBC/PKCS5Padding";
    public static final String SYNC_CIPHER_MODE_UNPADDED = "AES/CBC/NoPadding";
    public static final String SYNC_CIPHER_NAME = "AES";

    /**
     * For use in encoding/decoding X509 public keys.
     */
    public static final String PUBLIC_KEY_ALGORITHM = "RSA";
    public static final String PUBLIC_KEY_HEADER = "-----BEGIN PUBLIC KEY-----";
    public static final String PUBLIC_KEY_FOOTER = "-----END PUBLIC KEY-----";

    /**
     * Blocksize in bytes
     */
    public static final int SYNC_CIPHER_BLOCKSIZE = 16;
    public static final int CHALLENGE_BYTES = 8;

    /**
     * Maximum request time skew.  Request is considered invalid if it
     * exceeds this window.
     */
    public static final long MAX_TIME_SKEW = TimeUnit.SECONDS.toMillis(300);

    /**
     * Random session IV.
     */
    public static final String SESSION_IV_DELIM = "#";

    public static final int SESSION_IV_LEN = 16;

    /**
     * Sec response keys
     */
    public static final String VERSION_KEY = "v";
    public static final String ENCRYPTION_KEY = "c";
    public static final String CERT_AUTH_KEY = "ca";

    protected static final SecureRandom RANDOM = new SecureRandom();

    protected static int findSessionIVLen(String cipher)
          throws XrootdException {
        int index = cipher.indexOf(SESSION_IV_DELIM);
        if (index == cipher.length() - 1) {
            throw new XrootdException(kGSErrError,
                  "malformed cipher " + cipher);
        }

        return index < 0 ? 0 : Integer.valueOf(cipher.substring(index + 1));
    }

    /**
     * Generate a new challenge string to be used in server-client
     * communication
     * @return challenge string
     */
    public static String generateChallengeString() {
        byte[] challengeBytes = new byte[CHALLENGE_BYTES];

        /*
         * RANDOM.nextBytes(...) can not be used, since this generates
         * signed bytes. Upon encoding as string, Java will map negative bytes
         * to 63 (ASCII 'A'). As this would affect the randomness of the
         * challenge string, use the following loop instead.
         */
        for (int i = 0; i < CHALLENGE_BYTES; i++) {
            challengeBytes[i] = (byte) RANDOM.nextInt(Byte.MAX_VALUE);
        }

        String challenge = new String(challengeBytes, US_ASCII);

        LOGGER.debug("Generated new challenge string: {}.", challenge);

        return challenge;
    }

    protected final GSICredentialManager credentialManager;

    protected DHSession dhSession;
    protected RSASession rsaSession;
    protected DHBufferHandler bufferHandler;
    protected String challenge = "";
    protected long lastRequest;
    protected boolean noPadding;

    protected GSIRequestHandler(GSICredentialManager credentialManager) {
        this.credentialManager = credentialManager;
        rsaSession = new RSASession();
    }

    /*
     *  Will be either PROTO_WITH_DELEGATION or PROTO_PRE_DELEGATION.
     */
    public abstract int getProtocolVersion();

    /*
     *  Will be either SYNC_CIPHER_MODE_PADDED or SYNC_CIPHER_MODE_UNPADDED
     */
    protected abstract String getSyncCipherMode();

    /**
     * Assumes the dhSession has been finalized.
     *
     * @param receivedBuckets from the request
     * @return the main bucket as a nested bucket buffer
     */
    protected NestedBucketBuffer
    decryptMainBucketWithSessionKey(Map<BucketType, GSIBucket> receivedBuckets,
          String step)
          throws NoSuchPaddingException,
          InvalidAlgorithmParameterException,
          NoSuchAlgorithmException, IllegalBlockSizeException,
          BadPaddingException, NoSuchProviderException,
          InvalidKeyException, IOException, XrootdException {
        LOGGER.debug("Decrypting main bucket with session key.");
        RawBucket encryptedBucket = (RawBucket) receivedBuckets.get(kXRS_main);
        byte[] encrypted = encryptedBucket.getContent();
        byte[] decrypted = dhSession.decrypt(SYNC_CIPHER_MODE_PADDED,
              SYNC_CIPHER_NAME,
              SYNC_CIPHER_BLOCKSIZE,
              encrypted);
        ByteBuf buffer = wrappedBuffer(decrypted);
        NestedBucketBuffer nested
              = GSIBucketUtils.deserializeNested(kXRS_main, buffer);

        if (LOGGER.isTraceEnabled()) {
            StringBuilder builder = new StringBuilder();
            nested.dump(builder, step, 0);
            LOGGER.trace(builder.toString());
        }

        return nested;
    }

    /**
     * @param sign if true, use the rsaCipher (assumed to be initialized with
     *             local private key) to sign the params.
     * @return encoded DH parameters, either signed or unsigned.
     */
    protected byte[] dhParams(boolean sign) throws IOException, BadPaddingException,
          IllegalBlockSizeException {
        LOGGER.debug("Getting encoded dh paramters (signed: {}).", sign);

        byte[] cipher = dhSession.getEncodedDHMaterial().getBytes();

        if (sign) {
            LOGGER.debug("Signing encoded dh paramters.");
            return rsaSession.encrypt(cipher);
        }

        return cipher;
    }

    /**
     * Pull out the string content of the kXRS_x509 bucket and convert it
     * into a cert chain.
     *
     * @param nestedBuckets containing the x509 bucket.
     * @return the cert chain
     */
    protected X509Certificate[] extractChain(Map<BucketType, GSIBucket> nestedBuckets)
          throws XrootdException, IOException {
        LOGGER.debug("Extracting X509Certificate chain.");
        GSIBucket clientX509Bucket = nestedBuckets.get(kXRS_x509);

        if (clientX509Bucket == null) {
            throw new XrootdException(kGSErrDecodeBuffer, "No kXRS_x509 bucket.");
        }

        String clientX509 = ((StringBucket) clientX509Bucket).getContent();

        ByteArrayInputStream stream
              = new ByteArrayInputStream(clientX509.getBytes(US_ASCII));
        X509Certificate[] proxyCertChain =
              CertificateUtils.loadCertificateChain(stream, PEM);
        if (proxyCertChain.length == 0) {
            throw new IllegalArgumentException("Could not parse x509 " +
                  "certificate "
                  + "from input "
                  + "stream!");
        }

        return proxyCertChain;
    }

    /**
     * For the pre-4.9 protocol, the DH client params are sent in the clear
     * (unsigned) in the kXRS_puk bucket.
     *
     * For 4.9+, the params are sent in the kXRS_cipher bucket, and are
     * signed with the client's private key, so they must be
     * decrypted.  This method assumes that the rsaCipher has
     * already been initialized for decryption using the
     * public key sent by the client in the kXRS_puk bucket.
     *
     * @param receivedBuckets
     * @param bucketType  kXRS_cipher or kXRS_puk.
     */
    protected void finalizeSessionKey(Map<BucketType, GSIBucket> receivedBuckets,
          BucketType bucketType)
          throws IOException, GeneralSecurityException, XrootdException {
        LOGGER.debug("Finalizing session key using bucket type {}.",
              bucketType.name());

        StringBucket dhMessage = null;

        switch (bucketType) {
            case kXRS_puk:
                dhMessage = (StringBucket) receivedBuckets.get(kXRS_puk);
                LOGGER.debug("DH message (params) from kXRS_puk: {}.",
                      dhMessage.getContent());
                break;
            case kXRS_cipher:
                RawBucket encryptedBucket = (RawBucket) receivedBuckets.get(kXRS_cipher);
                byte[] encrypted = encryptedBucket.getContent();
                LOGGER.debug("Decrypting cipher bucket using public key, "
                            + "buffer length {}.",
                      encrypted.length);
                byte[] decrypted = rsaSession.decrypt(encrypted);
                ByteBuf buffer = wrappedBuffer(decrypted);
                dhMessage = StringBucket.deserialize(kXRS_cipher, buffer);
                LOGGER.debug("DH message (params) from kXRS_cipher "
                            + "after decryption: {}.",
                      dhMessage.getContent());
                break;
            default:
                throw new XrootdException(kGSErrCreateBucket, "Unexpected bucketType "
                      + bucketType + " in "
                      + "finalizeSessionKey: "
                      + bucketType.name());
        }

        dhSession.finaliseKeyAgreement(dhMessage.getContent());

        /*
         * For handling signed hashes, if and when the security level
         * requires it.
         */
        bufferHandler = new DHBufferHandler(dhSession,
              getSyncCipherMode(),
              SYNC_CIPHER_NAME,
              SYNC_CIPHER_BLOCKSIZE);

        LOGGER.debug("Constructed buffer handler for signed hash use.");
    }

    protected boolean isRequestExpired() {
        if (lastRequest == 0L) {
            lastRequest = System.currentTimeMillis();
            return false;
        }

        return System.currentTimeMillis() - lastRequest >= MAX_TIME_SKEW;
    }

    /**
     * Generate a new challenge string.  Sign the sender's challenge string
     * (assumes rsaCipher has been initialized for encryption).
     *
     * If the response including this bucket follows session key finalization,
     * the bucket needs to be encrypted.  This is indicated by the switch logic
     * on the step parameter.
     *
     * @return main bucket either encrypted or not, depending on step
     */
    protected GSIBucket
    postProcessMainBucket(Map<BucketType, GSIBucket> buckets,
          Optional<String> serializedX509,
          int step)
          throws BadPaddingException, IllegalBlockSizeException,
          NoSuchProviderException, NoSuchPaddingException,
          NoSuchAlgorithmException, InvalidKeyException,
          InvalidAlgorithmParameterException, XrootdException,
          IOException {
        LOGGER.debug("Post-processing main bucket.");
        challenge = GSIRequestHandler.generateChallengeString();
        byte[] signedRtag = signRtagChallenge(buckets);

        RawBucket signedRtagBucket =
              new RawBucket(BucketType.kXRS_signed_rtag, signedRtag);
        StringBucket randomTagBucket = new StringBucket(kXRS_rtag, challenge);

        BucketType x509Type = step == kXGS_pxyreq ? kXRS_x509_req : kXRS_x509;

        StringBucket x509Bucket = serializedX509.isPresent() ?
              new StringBucket(x509Type, serializedX509.get()) : null;

        switch (step) {
            /*
             * This step requires that it be signed using the session key.
             */
            case kXGS_pxyreq:
            case kXGC_sigpxy:
            case kXGC_cert:
                LOGGER.debug("Building encrypted main bucket.");
                return buildEncryptedMainBucket(step,
                      signedRtagBucket,
                      randomTagBucket,
                      x509Bucket);
            default:
                LOGGER.debug("Building unencrypted main bucket.");
                Map<BucketType, GSIBucket> nestedBuckets = new EnumMap<>(BucketType.class);
                nestedBuckets.put(signedRtagBucket.getType(), signedRtagBucket);
                nestedBuckets.put(randomTagBucket.getType(), randomTagBucket);
                if (x509Bucket != null) {
                    nestedBuckets.put(x509Bucket.getType(), x509Bucket);
                }
                return new NestedBucketBuffer(kXRS_main,
                      PROTOCOL,
                      step,
                      nestedBuckets);
        }
    }

    /**
     * @param nestedBuckets containing the x509 certificate bucket
     * @param toMatch if a sender public key has already been extracted.
     * @return the extracted and verified certificate chain
     */
    protected X509Certificate[]
    processRSAVerification(Map<BucketType, GSIBucket> nestedBuckets,
          Optional<PublicKey> toMatch)
          throws InvalidKeyException, IOException, XrootdException {
        LOGGER.debug("Processing RSA cert chain verification; "
                    + "previous key to match? {}.",
              toMatch.isPresent());
        X509Certificate[] proxyCertChain = extractChain(nestedBuckets);
        credentialManager.getCertChainValidator().validate(proxyCertChain);
        X509Certificate certificate = proxyCertChain[0];
        if (toMatch.isPresent() &&
              !toMatch.get().equals(certificate.getPublicKey())) {
            throw new InvalidKeyException(
                  "Error in cryptographic operations; received "
                        + "two different public keys.");
        }

        return proxyCertChain;
    }

    protected void updateLastRequest() {
        lastRequest = System.currentTimeMillis();
    }

    /*
     *  Checks that the sender can support the algorithm used by dCache.
     */
    protected String validateCiphers(String[] algorithms) throws XrootdException {
        LOGGER.debug("Validating cipher algorithm.");
        String selectedCipher = null;
        for (String algorithm : algorithms) {
            LOGGER.debug("checking cipher algorithm {}.", algorithm);
            int ivIndex = algorithm.indexOf(SESSION_IV_DELIM);
            String cipher;
            if (ivIndex > 0) {
                cipher = algorithm.substring(0, ivIndex);
            } else {
                cipher = algorithm;
            }

            if (SUPPORTED_CIPHER_ALGORITHM.contains(cipher)) {
                selectedCipher = algorithm;
                break;
            }
        }

        if (selectedCipher == null) {
            throw new XrootdException(kXR_error, "all sender ciphers are "
                  + "unsupported: " + Arrays.asList(algorithms));
        }

        LOGGER.debug("Selected cipher algorithm {}", selectedCipher);

        return selectedCipher;
    }

    /*
     *  Checks that the sender can support the crypto mode used by dCache.
     */
    protected void validateCryptoMode(String cryptoMode) throws XrootdException {
        LOGGER.debug("Validating crypto mode.");
        if (!cryptoMode.equalsIgnoreCase(CRYPTO_MODE)) {
            if (cryptoMode.equalsIgnoreCase(CRYPTO_MODE_NO_PAD)) {
                noPadding = true;
                return;
            }
            throw new XrootdException(kXR_error, cryptoMode + " not supported.");
        }
    }

    /*
     *  Checks that the sender can support the digest used by dCache.
     */
    protected String validateDigests(String[] digests)
          throws XrootdException {
        LOGGER.debug("Validating cipher digests.");
        String selectedDigest = null;
        for (String digest : digests) {
            if (SUPPORTED_DIGESTS.contains(digest)) {
                selectedDigest = digest;
                break;
            }
        }

        if (selectedDigest == null) {
            throw new XrootdException(kXR_error, "all sender digests are "
                  + "unsupported: " + Arrays.asList(digests));
        }

        return selectedDigest;
    }

    /**
     * From the main bucket extract the challenge tag signed by the sender.
     * Decrypt this using the rsaCipher (assumes it has been intialized
     * using the received public key).  Check that it matches the token
     * previously generated.
     */
    protected void verifySignedRTag(Map<BucketType, GSIBucket> nestedBuckets)
          throws XrootdException, BadPaddingException,
          IllegalBlockSizeException, IOException {
        GSIBucket signedRTagBucket = nestedBuckets.get(kXRS_signed_rtag);
        byte[] signedRTag = ((RawBucket) signedRTagBucket).getContent();

        byte[] rTag = rsaSession.decrypt(signedRTag);
        String rTagString = new String(rTag, US_ASCII);

        // check that the challenge sent in the previous step matches
        if (!challenge.equals(rTagString)) {
            LOGGER.error("The challenge is {}, the serialized rTag is {}." +
                        "signature of challenge tag has been "
                        + "proven wrong!!",
                  challenge, rTagString);
            throw new XrootdException(kGSErrBadRndmTag,
                  "Sender did not present correct" +
                        "challenge response!");
        }

        LOGGER.debug("signature of challenge tag ok. Challenge: " +
              "{}, rTagString: {}", challenge, rTagString);
    }

    /*
     * Utility for encoding and encrypting the main bucket using the session key.
     * Assumes session key has been finalized.
     */
    private RawBucket buildEncryptedMainBucket(int step,
          GSIBucket... buckets)
          throws XrootdException, NoSuchPaddingException,
          InvalidAlgorithmParameterException,
          NoSuchAlgorithmException, IllegalBlockSizeException,
          BadPaddingException, NoSuchProviderException,
          InvalidKeyException {
        if (dhSession == null) {
            throw new XrootdException(kXR_DecryptErr, "trying to encrypt message "
                  + "without session key.");
        }

        /*
         *  Construct the main bucket with the 8 byte protocol-step header,
         *  but without bucket type header.
         */
        ByteBuf buffer = PooledByteBufAllocator.DEFAULT.buffer();

        byte[] bytes = PROTOCOL.getBytes(US_ASCII);
        buffer.writeBytes(bytes);
        buffer.writeZero(4 - bytes.length);
        buffer.writeInt(step);
        for (GSIBucket bucket : buckets) {
            if (bucket != null) {
                bucket.serialize(buffer);
            }
        }
        buffer.writeInt(BucketType.kXRS_none.getCode());
        byte[] raw = new byte[buffer.readableBytes()];
        buffer.getBytes(0, raw);
        buffer.release();
        byte[] encrypted = dhSession.encrypt(SYNC_CIPHER_MODE_PADDED,
              SYNC_CIPHER_NAME,
              SYNC_CIPHER_BLOCKSIZE,
              raw);
        return new RawBucket(kXRS_main, encrypted);
    }

    /**
     * @param nestedBuckets containing kXRS_tag
     * @return the rtag challenge signed using the rsaCipher (assumed to be
     *         initialized with the local private key).
     */
    private byte[] signRtagChallenge(Map<BucketType, GSIBucket> nestedBuckets)
          throws BadPaddingException, IllegalBlockSizeException,
          IOException {
        StringBucket rtagBucket = (StringBucket) nestedBuckets.get(kXRS_rtag);
        byte[] rtag = rtagBucket.getContent().getBytes();
        LOGGER.debug("Signing sender's random challenge tag of length {}.",
              rtag.length);
        return rsaSession.encrypt(rtag);
    }
}
