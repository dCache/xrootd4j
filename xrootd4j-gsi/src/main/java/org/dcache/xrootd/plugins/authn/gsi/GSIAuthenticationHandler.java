/**
 * Copyright (C) 2011-2015 dCache.org <support@dcache.org>
 *
 * This file is part of xrootd4j.
 *
 * xrootd4j is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * xrootd4j is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with xrootd4j.  If not, see http://www.gnu.org/licenses/.
 */
package org.dcache.xrootd.plugins.authn.gsi;

import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.impl.CertificateUtils;
import io.netty.buffer.ByteBuf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.security.auth.Subject;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.plugins.AuthenticationHandler;
import org.dcache.xrootd.protocol.XrootdProtocol;
import org.dcache.xrootd.protocol.messages.AuthenticationRequest;
import org.dcache.xrootd.protocol.messages.AuthenticationResponse;
import org.dcache.xrootd.protocol.messages.OkResponse;
import org.dcache.xrootd.protocol.messages.XrootdResponse;
import org.dcache.xrootd.security.NestedBucketBuffer;
import org.dcache.xrootd.security.RawBucket;
import org.dcache.xrootd.security.StringBucket;
import org.dcache.xrootd.security.XrootdBucket;

import static io.netty.buffer.Unpooled.wrappedBuffer;
import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.dcache.xrootd.protocol.XrootdProtocol.*;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.*;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType.*;

/**
 * Handler for xrootd-security message exchange based on the GSI protocol.
 * Loosely based on the first reverse-engineering of xrootdsec-gsi, done by
 * Martin Radicke.
 *
 * @author tzangerl
 *
 */
public class GSIAuthenticationHandler implements AuthenticationHandler
{
    public static final String PROTOCOL = "gsi";
    public static final String PROTOCOL_VERSION= "10200";
    public static final String CRYPTO_MODE = "ssl";
    /** for now, we limit ourselves to AES-128 with CBC blockmode. */
    public static final String SUPPORTED_CIPHER_ALGORITHMS = "aes-128-cbc";
    public static final String SUPPORTED_DIGESTS = "sha1:md5";

    private static final Logger _logger =
        LoggerFactory.getLogger(GSIAuthenticationHandler.class);

    /**
     * RSA algorithm, no block chaining mode (not a block-cipher) and PKCS1
     * padding, which is recommended to be used in conjunction with RSA
     */
    private static final String SERVER_ASYNC_CIPHER_MODE = "RSA/NONE/PKCS1Padding";

    /** the sync cipher mode supported by the server. Unless this is made
     * configurable (todo), it has to match the SUPPORTED_CIPHER_ALGORITHMS
     * advertised by the server
     */
    private static final String SERVER_SYNC_CIPHER_MODE = "AES/CBC/PKCS5Padding";
    private static final String SERVER_SYNC_CIPHER_NAME = "AES";
    /** blocksize in bytes */
    private static final int SERVER_SYNC_CIPHER_BLOCKSIZE = 16;
    private static final int CHALLENGE_BYTES = 8;

    /** cryptographic helper classes */
    private static final SecureRandom _random = new SecureRandom();

    /** certificates/keys/trust-anchors */
    private final X509Credential _hostCredential;
    private final X509CertChainValidator _validator;

    private String _challenge = "";
    private Cipher _challengeCipher;
    private DHSession _dhSession;

    /**
     * Container for principals and credentials found during the authentication
     * process.
     */
    private final Subject _subject;

    private boolean _finished = false;

    public GSIAuthenticationHandler(X509Credential hostCredential, X509CertChainValidator validator) {
        _hostCredential = hostCredential;
        _validator = validator;
        _subject = new Subject();
    }

    class XrootdBucketContainer {
        private final int _size;
        private final List<XrootdBucket> _buckets;

        public XrootdBucketContainer(List<XrootdBucket> buckets, int size) {
            _buckets = buckets;
            _size = size;
        }

        public int getSize() {
            return _size;
        }

        public List<XrootdBucket> getBuckets() {
            return _buckets;
        }
    }

    /**
     * dispatcher function that initializes the diffie-hellman key agreement
     * session, checks the request for the correct protocol and calls the
     * actual handler functions.
     *
     * @see #handleCertReqStep
     * @see #handleCertStep
     */
    @Override
    public XrootdResponse<AuthenticationRequest> authenticate(AuthenticationRequest request)
        throws XrootdException
    {
        try {
            if (_dhSession == null) {
                _dhSession = new DHSession();
            }
        } catch (GeneralSecurityException gssex) {
            _logger.error("Error setting up cryptographic classes: {}",
                          gssex);
            throw new XrootdException(kXR_ServerError,
                                      "Server probably misconfigured.");
        }

        /* check whether the protocol matches */
        if (!PROTOCOL.equalsIgnoreCase(request.getProtocol())) {
            throw new XrootdException(kXR_InvalidRequest,
                                      "Specified Protocol " + request.getProtocol() +
                                      " is not the protocol that was negotiated.");
        }

        switch(request.getStep()) {
        case kXGC_none:
            return new OkResponse<>(request);
        case kXGC_certreq:
            return handleCertReqStep(request);
        case kXGC_cert:
            return handleCertStep(request);
        default:
            throw new XrootdException(kXR_InvalidRequest,
                                      "Error during authentication, " +
                                      "unknown processing step: "
                                      + request.getStep());
        }
    }

    /**
     * Handle the kXGC_certreq step, as signalled by the client. Load host
     * credentials, decode received kXR buckets and build a response
     * consisting of reply buckets.
     *
     * The cert-req step will consist of a client challenge (rTag) that is
     * signed by the server using its private key. The public key, needed
     * by the client for verification, is sent along with the response.
     *
     * Other information passed by the server include DH-parameters needed for
     * symmetric key exchange, a list of supported symmetric ciphers and
     * digests.
     *
     * @param request The received authentication request
     * @return AuthenticationResponse with kXR_authmore
     */
    private XrootdResponse<AuthenticationRequest>
        handleCertReqStep(AuthenticationRequest request)
        throws XrootdException
    {
        try {
            _challengeCipher = Cipher.getInstance(SERVER_ASYNC_CIPHER_MODE, "BC");
            _challengeCipher.init(Cipher.ENCRYPT_MODE, _hostCredential.getKey());

            Map<BucketType, XrootdBucket> buckets = request.getBuckets();
            NestedBucketBuffer buffer =
                ((NestedBucketBuffer) buckets.get(kXRS_main));

            StringBucket rtagBucket =
                (StringBucket) buffer.getNestedBuckets().get(kXRS_rtag);
            String rtag = rtagBucket.getContent();

            /* sign the rtag for the client */
            _challengeCipher.update(rtag.getBytes());
            byte [] signedRtag = _challengeCipher.doFinal();
            /* generate a new challenge, to be signed by the client */
            _challenge = generateChallengeString();
            /* send DH params */
            byte[] puk = _dhSession.getEncodedDHMaterial().getBytes();
            /* send host certificate */
            _hostCredential.getCertificate().getEncoded();

            String hostCertificateString =
                CertUtil.certToPEM(_hostCredential.getCertificate());

            XrootdBucketContainer responseBuckets =
                            buildCertReqResponse(signedRtag,
                                                 _challenge,
                                                 CRYPTO_MODE,
                                                 puk,
                                                 SUPPORTED_CIPHER_ALGORITHMS,
                                                 SUPPORTED_DIGESTS,
                                                 hostCertificateString);

            return new AuthenticationResponse(request,
                                              XrootdProtocol.kXR_authmore,
                                              responseBuckets.getSize(),
                                              PROTOCOL,
                                              kXGS_cert,
                                              responseBuckets.getBuckets());
        } catch (InvalidKeyException ikex) {
            _logger.error("Configured host-key could not be used for" +
                          "signing rtag: {}", ikex);
            throw new XrootdException(kXR_ServerError,
                                      "Internal error occurred when trying " +
                                      "to sign client authentication tag.");
        } catch (CertificateEncodingException cee) {
            _logger.error("Could not extract contents of server certificate:" +
                          " {}", cee);
            throw new XrootdException(kXR_ServerError,
                                      "Internal error occurred when trying " +
                                      "to send server certificate.");
        } catch (IOException | GeneralSecurityException gssex) {
            _logger.error("Problems during signing of client authN tag " +
                          "(algorithm {}): {}", SERVER_ASYNC_CIPHER_MODE, gssex);
            throw new XrootdException(kXR_ServerError,
                                      "Internal error occurred when trying " +
                                      "to sign client authentication tag.");
        }
    }

    /**
     * Handle the second step (reply by client to authmore).
     * In this step the DH-symmetric key agreement is finalized, thus obtaining
     * a symmetric key that can subsequently be used to encrypt the message
     * exchange.
     *
     * The challenge cipher sent by the server in the kXR_cert step is sent
     * back. The cipher is signed by the client's private key, we can use the
     * included public key to verify it.
     *
     * Also, the client's X.509 certificate will be checked for trustworthiness.
     * Presently, this check is limited to verifying whether the issuer
     * certificate is trusted and the certificate is not contained in a CRL
     * installed on the server.
     *
     * @param request AuthenticationRequest received by the client
     * @return OkResponse (verification is okay)
     */
    private XrootdResponse<AuthenticationRequest>
        handleCertStep(AuthenticationRequest request)
        throws XrootdException
    {
        try {
            Map<BucketType, XrootdBucket> receivedBuckets = request.getBuckets();

            /* the stuff we want to get is the encrypted material in kXRS_main */
            RawBucket encryptedBucket =
                (RawBucket) receivedBuckets.get(kXRS_main);

            byte [] encrypted = encryptedBucket.getContent();

            StringBucket dhMessage =
                (StringBucket) receivedBuckets.get(kXRS_puk);

            _dhSession.finaliseKeyAgreement(dhMessage.getContent());
            byte [] decrypted = _dhSession.decrypt(SERVER_SYNC_CIPHER_MODE,
                                                   SERVER_SYNC_CIPHER_NAME,
                                                   SERVER_SYNC_CIPHER_BLOCKSIZE,
                                                   encrypted);

            ByteBuf buffer = wrappedBuffer(decrypted);
            NestedBucketBuffer nestedBucket =
                NestedBucketBuffer.deserialize(kXRS_main, buffer);

            XrootdBucket clientX509Bucket =
                nestedBucket.getNestedBuckets().get(kXRS_x509);
            String clientX509 =
                ((StringBucket) clientX509Bucket).getContent();

            /* now it's time to verify the client's X509 certificate */
            X509Certificate[] proxyCertChain = CertificateUtils.loadCertificateChain(new ByteArrayInputStream(clientX509.getBytes(US_ASCII)), CertificateUtils.Encoding.PEM);
            if (proxyCertChain.length == 0) {
                throw new IllegalArgumentException("Could not parse user " +
                                                   "certificate from input stream!");
            }
            X509Certificate proxyCert = proxyCertChain[0];
            _logger.info("The proxy-cert has the subject {} and the issuer {}",
                         proxyCert.getSubjectDN(),
                         proxyCert.getIssuerDN());

            _validator.validate(proxyCertChain);
            _subject.getPublicCredentials().add(proxyCertChain);

            _challengeCipher.init(Cipher.DECRYPT_MODE, proxyCert.getPublicKey());

            XrootdBucket signedRTagBucket =
                nestedBucket.getNestedBuckets().get(kXRS_signed_rtag);
            byte[] signedRTag = ((RawBucket) signedRTagBucket).getContent();

            byte[] rTag = _challengeCipher.doFinal(signedRTag);
            String rTagString = new String(rTag, US_ASCII);

            // check that the challenge sent in the previous step matches
            if (!_challenge.equals(rTagString)) {
               _logger.error("The challenge is {}, the serialized rTag is {}." +
                             "signature of challenge tag has been proven wrong!!",
                             _challenge, rTagString);
               throw new XrootdException(kXR_InvalidRequest,
                                         "Client did not present correct" +
                                         "challenge response!");
            }
            _logger.debug("signature of challenge tag ok. Challenge: " +
                          "{}, rTagString: {}", _challenge, rTagString);

            _finished = true;

            return new OkResponse<>(request);
        } catch (InvalidKeyException ikex) {
            _logger.error("The key negotiated by DH key exchange appears to " +
                          "be invalid: {}", ikex);
            throw new XrootdException(kXR_InvalidRequest,
                                      "Could not decrypt client" +
                                      "information with negotiated key.");
        } catch (InvalidKeySpecException iksex) {
            _logger.error("DH key negotiation caused problems{}", iksex);
            throw new XrootdException(kXR_InvalidRequest,
                                      "Could not find key negotiation " +
                                      "parameters.");
        } catch (IOException ioex) {
            _logger.error("Could not deserialize main nested buffer {}", ioex);
            throw new XrootdException(kXR_IOError,
                                      "Could not decrypt encrypted " +
                                      "client message.");
        } catch (GeneralSecurityException gssex) {
            _logger.error("Error during decrypting/server-side key exchange: {}",
                          gssex);
            throw new XrootdException(kXR_ServerError,
                                      "Error in server-side cryptographic " +
                                      "operations.");
        }
    }

    /**
     * Build the server response to the kXGC_certReq request.
     * Such a response will include the signed challenge sent by the client,
     * a new challenge created by the server, the cryptoMode (typically SSL),
     * DH key exchange parameters, a list of supported ciphers, a list of
     * supported digests and a PEM-encoded host certificate.
     *
     * @param signedChallenge
     * @param newChallenge
     * @param cryptoMode
     * @param puk
     * @param supportedCiphers
     * @param supportedDigests
     * @param hostCertificate
     * @return List with the above parameters plus size in bytes of the bucket
     *         list.
     */
    private XrootdBucketContainer buildCertReqResponse(byte[] signedChallenge,
                                                       String newChallenge,
                                                       String cryptoMode,
                                                       byte [] puk,
                                                       String supportedCiphers,
                                                       String supportedDigests,
                                                       String hostCertificate)
    {
        int responseLength = 0;
        List<XrootdBucket> responseList = new ArrayList<>();

        RawBucket signedRtagBucket =
            new RawBucket(BucketType.kXRS_signed_rtag, signedChallenge);
        StringBucket randomTagBucket = new StringBucket(kXRS_rtag, newChallenge);

        Map<BucketType, XrootdBucket> nestedBuckets =
            new EnumMap<>(BucketType.class);
        nestedBuckets.put(signedRtagBucket.getType(), signedRtagBucket);
        nestedBuckets.put(randomTagBucket.getType(), randomTagBucket);

        NestedBucketBuffer mainBucket = new NestedBucketBuffer(kXRS_main,
                                                               PROTOCOL,
                                                               kXGS_cert,
                                                               nestedBuckets);

        StringBucket cryptoBucket = new StringBucket(kXRS_cryptomod, CRYPTO_MODE);
        responseLength += cryptoBucket.getSize();
        responseList.add(cryptoBucket);
        responseLength += mainBucket.getSize();
        responseList.add(mainBucket);

        RawBucket dhPublicBucket = new RawBucket(kXRS_puk, puk);
        responseLength += dhPublicBucket.getSize();
        responseList.add(dhPublicBucket);

        StringBucket cipherBucket = new StringBucket(kXRS_cipher_alg,
                                                     supportedCiphers);
        responseLength += cipherBucket.getSize();
        responseList.add(cipherBucket);

        StringBucket digestBucket = new StringBucket(kXRS_md_alg,
                                                     supportedDigests);
        responseLength += digestBucket.getSize();
        responseList.add(digestBucket);

        StringBucket hostCertBucket =
            new StringBucket(kXRS_x509,
                             hostCertificate);
        responseLength += hostCertBucket.getSize();
        responseList.add(hostCertBucket);

        return new XrootdBucketContainer(responseList, responseLength);
    }

    /**
     * Generate a new challenge string to be used in server-client
     * communication
     * @return challenge string
     */
    private String generateChallengeString() {
        byte[] challengeBytes = new byte[CHALLENGE_BYTES];

        /*
         * _random.nextBytes(...) can not be used, since this generates
         * signed bytes. Upon encoding as string, Java will map negative bytes
         * to 63 (ASCII 'A'). As this would affect the randomness of the
         * challenge string, use the following loop instead.
         */
        for (int i = 0; i < CHALLENGE_BYTES; i++) {
            challengeBytes[i] = (byte) _random.nextInt(Byte.MAX_VALUE);
        }

        return new String(challengeBytes, US_ASCII);
    }

    /**
     * @return the protocol supported by this client. The protocol string also
     * contains metainformation such as the host-certificate subject hash.
     */
    @Override
    public String getProtocol() {
        /* hashed principals are cached in CertUtil */
        String subjectHash =
            CertUtil.computeMD5Hash(_hostCredential.getCertificate().getIssuerX500Principal());

        return "&P=" + PROTOCOL + "," +
                "v:" + PROTOCOL_VERSION + "," +
                "c:" + CRYPTO_MODE + "," +
                "ca:" + subjectHash;
    }

    @Override
    public Subject getSubject() {
        return _subject;
    }

    @Override
    public boolean isCompleted() {
        return _finished;
    }
}
