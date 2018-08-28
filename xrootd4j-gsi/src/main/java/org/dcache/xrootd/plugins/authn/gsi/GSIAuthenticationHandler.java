/**
 * Copyright (C) 2011-2018 dCache.org <support@dcache.org>
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

import javax.crypto.Cipher;
import javax.security.auth.Subject;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
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
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_IOError;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_InvalidRequest;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_ServerError;
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
public class GSIAuthenticationHandler extends BaseGSIAuthenticationHandler
                implements AuthenticationHandler
{
    /**
     * Container for principals and credentials found during the authentication
     * process.
     */
    private final Subject subject;

    private String challenge = "";
    private Cipher challengeCipher;
    private DHSession dhSession;

    private boolean finished = false;

    public GSIAuthenticationHandler(X509Credential hostCredential,
                                    X509CertChainValidator validator,
                                    String certDir)
    {
        super(hostCredential, validator, certDir);
        subject = new Subject();
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
            if (dhSession == null) {
                dhSession = new DHSession(true);
            }
        } catch (GeneralSecurityException gssex) {
            LOGGER.error("Error setting up cryptographic classes: {}", gssex.getMessage());
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
            challengeCipher = Cipher.getInstance(SERVER_ASYNC_CIPHER_MODE, "BC");
            challengeCipher.init(Cipher.ENCRYPT_MODE, credential.getKey());

            Map<BucketType, XrootdBucket> buckets = request.getBuckets();
            NestedBucketBuffer buffer =
                ((NestedBucketBuffer) buckets.get(kXRS_main));

            StringBucket rtagBucket =
                (StringBucket) buffer.getNestedBuckets().get(kXRS_rtag);
            String rtag = rtagBucket.getContent();

            /* sign the rtag for the client */
            challengeCipher.update(rtag.getBytes());
            byte [] signedRtag = challengeCipher.doFinal();
            /* generate a new challenge, to be signed by the client */
            challenge = generateChallengeString();
            /* send DH params */
            byte[] puk = dhSession.getEncodedDHMaterial().getBytes();
            /* send host certificate */
            credential.getCertificate().getEncoded();

            String hostCertificateString =
                CertUtil.certToPEM(credential.getCertificate());

            XrootdBucketContainer responseBuckets =
                            buildCertReqResponse(signedRtag,
                                                 challenge,
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
            LOGGER.error("Configured host-key could not be used for" +
                          "signing rtag: {}", ikex.getMessage());
            throw new XrootdException(kXR_ServerError,
                                      "Internal error occurred when trying " +
                                      "to sign client authentication tag.");
        } catch (CertificateEncodingException cee) {
            LOGGER.error("Could not extract contents of server certificate:" +
                          " {}", cee.getMessage());
            throw new XrootdException(kXR_ServerError,
                                      "Internal error occurred when trying " +
                                      "to send server certificate.");
        } catch (IOException | GeneralSecurityException gssex) {
            LOGGER.error("Problems during signing of client authN tag " +
                          "(algorithm {}): {}", SERVER_ASYNC_CIPHER_MODE,
                          gssex.getMessage() == null ?
                          gssex.getClass().getName() : gssex.getMessage());
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

            dhSession.finaliseKeyAgreement(dhMessage.getContent());
            byte [] decrypted = dhSession.decrypt(SERVER_SYNC_CIPHER_MODE,
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
            X509Certificate[] proxyCertChain =
                            CertificateUtils.loadCertificateChain(new ByteArrayInputStream(clientX509.getBytes(US_ASCII)),
                                                                  CertificateUtils.Encoding.PEM);
            if (proxyCertChain.length == 0) {
                throw new IllegalArgumentException("Could not parse user " +
                                                   "certificate from input stream!");
            }
            X509Certificate proxyCert = proxyCertChain[0];
            LOGGER.info("The proxy-cert has the subject {} and the issuer {}",
                         proxyCert.getSubjectDN(),
                         proxyCert.getIssuerDN());

            validator.validate(proxyCertChain);
            subject.getPublicCredentials().add(proxyCertChain);

            challengeCipher.init(Cipher.DECRYPT_MODE, proxyCert.getPublicKey());

            XrootdBucket signedRTagBucket =
                nestedBucket.getNestedBuckets().get(kXRS_signed_rtag);
            byte[] signedRTag = ((RawBucket) signedRTagBucket).getContent();

            byte[] rTag = challengeCipher.doFinal(signedRTag);
            String rTagString = new String(rTag, US_ASCII);

            // check that the challenge sent in the previous step matches
            if (!challenge.equals(rTagString)) {
               LOGGER.error("The challenge is {}, the serialized rTag is {}." +
                             "signature of challenge tag has been proven wrong!!",
                             challenge, rTagString);
               throw new XrootdException(kXR_InvalidRequest,
                                         "Client did not present correct" +
                                         "challenge response!");
            }
            LOGGER.trace("signature of challenge tag ok. Challenge: " +
                          "{}, rTagString: {}", challenge, rTagString);

            finished = true;

            return new OkResponse<>(request);
        } catch (InvalidKeyException ikex) {
            LOGGER.error("The key negotiated by DH key exchange appears to " +
                          "be invalid: {}", ikex.getMessage());
            throw new XrootdException(kXR_InvalidRequest,
                                      "Could not decrypt client" +
                                      "information with negotiated key.");
        } catch (InvalidKeySpecException iksex) {
            LOGGER.error("DH key negotiation caused problems {}", iksex.getMessage());
            throw new XrootdException(kXR_InvalidRequest,
                                      "Could not find key negotiation " +
                                      "parameters.");
        } catch (IOException ioex) {
            LOGGER.error("Could not deserialize main nested buffer {}",
                          ioex.getMessage() == null ?
                          ioex.getClass().getName() : ioex.getMessage());
            throw new XrootdException(kXR_IOError,
                                      "Could not decrypt encrypted " +
                                      "client message.");
        } catch (GeneralSecurityException gssex) {
            LOGGER.error("Error during decrypting/server-side key exchange: {}",
                          gssex.getMessage());
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
     * @return the protocol supported by this client. The protocol string also
     * contains metainformation such as the host-certificate subject hash.
     */
    @Override
    public String getProtocol()
    {
        /* hashed principals are cached in CertUtil */
        String subjectHash =
            CertUtil.computeMD5Hash(credential.getCertificate().getIssuerX500Principal());

        return "&P=" + PROTOCOL + "," +
                "v:" + PROTOCOL_VERSION + "," +
                "c:" + CRYPTO_MODE + "," +
                "ca:" + subjectHash;
    }

    @Override
    public Subject getSubject()
    {
        return subject;
    }

    @Override
    public boolean isCompleted()
    {
        return finished;
    }
}
