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
package org.dcache.xrootd.plugins.authn.gsi.post49;

import static org.dcache.xrootd.plugins.authn.gsi.GSIBucketUtils.getLengthForRequest;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_DecryptErr;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_authmore;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType.kXRS_cipher;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType.kXRS_clnt_opts;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType.kXRS_cryptomod;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType.kXRS_message;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType.kXRS_puk;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType.kXRS_x509;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.getServerStep;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.kGSErrError;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.kGSErrSerialBuffer;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.kXGC_cert;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.kXGC_sigpxy;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.kXGS_pxyreq;

import eu.emi.security.authn.x509.impl.PEMCredential;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;
import java.util.Optional;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.security.auth.Subject;
import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.plugins.authn.gsi.CertUtil;
import org.dcache.xrootd.plugins.authn.gsi.GSIBucket;
import org.dcache.xrootd.plugins.authn.gsi.GSIBucketContainer;
import org.dcache.xrootd.plugins.authn.gsi.GSIBucketContainerBuilder;
import org.dcache.xrootd.plugins.authn.gsi.GSIBucketUtils.BucketData;
import org.dcache.xrootd.plugins.authn.gsi.GSIBucketUtils.BucketSerializer;
import org.dcache.xrootd.plugins.authn.gsi.GSIBucketUtils.BucketSerializerBuilder;
import org.dcache.xrootd.plugins.authn.gsi.GSICredentialManager;
import org.dcache.xrootd.plugins.authn.gsi.GSIServerRequestHandler;
import org.dcache.xrootd.plugins.authn.gsi.NestedBucketBuffer;
import org.dcache.xrootd.plugins.authn.gsi.StringBucket;
import org.dcache.xrootd.plugins.authn.gsi.UnsignedIntBucket;
import org.dcache.xrootd.protocol.messages.AuthenticationRequest;
import org.dcache.xrootd.protocol.messages.AuthenticationResponse;
import org.dcache.xrootd.protocol.messages.OkResponse;
import org.dcache.xrootd.protocol.messages.XrootdResponse;

/**
 * Implementation of server side of GSI handshake according to XrootD 4.9+.
 * Supports proxy delegation.
 */
public class GSIPost49ServerRequestHandler extends GSIServerRequestHandler {

    class ProxyRequestResponse extends GSIBucketContainerBuilder {

        GSIBucket mainBucket;
        StringBucket cryptoBucket;

        public ProxyRequestResponse(GSIBucket mainBucket,
              String cryptoMode) {
            this.mainBucket = mainBucket;
            cryptoBucket = new StringBucket(kXRS_cryptomod, cryptoMode);
        }

        @Override
        public GSIBucketContainer buildContainer() {
            return build(mainBucket, cryptoBucket);
        }
    }

    private boolean hasProxy;
    private boolean clientCanSignRequest;

    public GSIPost49ServerRequestHandler(Subject subject,
          GSICredentialManager credentialManager)
          throws XrootdException {
        super(subject, credentialManager);
    }

    @Override
    public int getProtocolVersion() {
        return PROTO_WITH_DELEGATION;
    }

    @Override
    public XrootdResponse<AuthenticationRequest> handleCertReqStep(
          AuthenticationRequest request, BucketData data) throws XrootdException {
        UnsignedIntBucket clientOpts
              = (UnsignedIntBucket) data.getBucketMap()
              .get(kXRS_clnt_opts);

        if (clientOpts != null) {
            clientCanSignRequest
                  = (Integer.lowestOneBit(clientOpts.getContent() >> 2) == 1);

            LOGGER.debug("Received kXRS_clnt_opts {}; can sign proxy requests {}.",
                  clientOpts.getContent(), clientCanSignRequest);
        }

        return handleCertReqStep(request, data, true, kXRS_cipher);
    }

    /**
     * Handle the second step (reply by client to authmore).
     *
     * This involves finalizing the session key, verifying rsa certificate
     * and decrypting and verifying the signed hash.
     *
     * A check is then made for the existence of a proxy.  If there
     * is none, a request is generated.
     *
     * @param request AuthenticationRequest received by the client
     * @return either an AuthenticationResponse with step kXGS_pxyreq if
     *         there is no currently valid proxy, or and OK response.
     */
    @Override
    public XrootdResponse<AuthenticationRequest>
    handleCertStep(AuthenticationRequest request, BucketData data) throws XrootdException {
        try {
            /*
             * Whether or not to match the openssl DH_compute_key_padded() routine.
             */
            dhSession.setPaddedKey(true);

            Map<BucketType, GSIBucket> receivedBuckets = data.getBucketMap();

            /*
             *  Just in case the client did not indicate the initialization
             *  vector prefix length, set the IV back to 0.
             */
            dhSession.setSessionIVLen(findSessionIVLen(validateCiphers(receivedBuckets)));

            validateDigests(receivedBuckets);

            PublicKey clientPuk = extractClientPublicKey(receivedBuckets);

            rsaSession.initializeForDecryption(clientPuk);

            finalizeSessionKey(receivedBuckets, kXRS_cipher);

            NestedBucketBuffer mainBucket
                  = decryptMainBucketWithSessionKey(receivedBuckets,
                  "kXGC_cert");

            X509Certificate[] certChain
                  = processRSAVerification(mainBucket.getNestedBuckets(),
                  Optional.of(clientPuk));

            subject.getPublicCredentials().add(certChain);

            verifySignedRTag(mainBucket.getNestedBuckets());

            /**
             *  Only send a sign request to the client if the client supports it.
             */
            if (clientCanSignRequest) {
                return getSigPxyResponse(certChain, request, mainBucket);
            }

            hasProxy = true;
            return new OkResponse<>(request);
        } catch (InvalidKeyException ikex) {
            cancelHandshake();
            LOGGER.error("The key negotiated by DH key exchange appears to " +
                  "be invalid: {}", ikex.getMessage());
            throw new XrootdException(kXR_DecryptErr,
                  "Could not decrypt client" +
                        "information with negotiated key.");
        } catch (IOException ioex) {
            cancelHandshake();
            LOGGER.error("Could not deserialize main nested buffer {}",
                  ioex.getMessage() == null ?
                        ioex.getClass().getName() : ioex.getMessage());
            throw new XrootdException(kGSErrSerialBuffer,
                  "Could not decrypt encrypted " +
                        "client message.");
        } catch (GeneralSecurityException gssex) {
            cancelHandshake();
            LOGGER.error("Error during decrypting/server-side key exchange: {}",
                  gssex.getMessage());
            throw new XrootdException(kGSErrError,
                  "Error in server-side cryptographic " +
                        "operations.");
        }
    }

    /**
     * Decrypt main bucket, check signed rtag, and then use included signed
     * certificate to finalize proxy (and send to the credential store).
     *
     * @return OKResponse if all is well.
     */
    @Override
    public XrootdResponse<AuthenticationRequest>
    handleSigPxyStep(AuthenticationRequest request, BucketData data) throws XrootdException {
        try {
            Map<BucketType, GSIBucket> receivedBuckets = data.getBucketMap();
            NestedBucketBuffer mainBucket
                  = decryptMainBucketWithSessionKey(receivedBuckets,
                  "kXGC_sigpxy");

            Map<BucketType, GSIBucket> nestedBuckets = mainBucket.getNestedBuckets();

            rsaSession.initializeForDecryption(credentialManager.getSenderPublicKey());
            verifySignedRTag(nestedBuckets);

            if (nestedBuckets.get(kXRS_x509) == null) {
                /*
                 *  Client cannot sign the request for some reason.
                 *  Rather than fail fast (we may not need the proxy),
                 *  report any message, and destroy the delegation request.
                 */

                StringBucket message = (StringBucket) nestedBuckets.get(kXRS_message);
                LOGGER.info("client cannot sign request; {}.",
                      message == null ? "(no message)" : message.getContent());

                cancelHandshake();
            } else {
                X509Certificate[] certChain = extractChain(nestedBuckets);
                request.getSession()
                      .setDelegatedCredential(credentialManager.finalizeDelegatedProxy(certChain));
                hasProxy = true;
            }

            return new OkResponse<>(request);
        } catch (InvalidKeyException ikex) {
            cancelHandshake();
            LOGGER.error("The key negotiated by DH key exchange appears to " +
                  "be invalid: {}", ikex.getMessage());
            throw new XrootdException(kXR_DecryptErr,
                  "Could not decrypt client" +
                        "information with negotiated key.");
        } catch (IOException ioex) {
            cancelHandshake();
            LOGGER.error("Could not deserialize main nested buffer {}",
                  ioex.getMessage() == null ?
                        ioex.getClass().getName() : ioex.getMessage());
            throw new XrootdException(kGSErrSerialBuffer,
                  "Could not decrypt encrypted " +
                        "client message.");
        } catch (GeneralSecurityException gssex) {
            cancelHandshake();
            LOGGER.error("Error during decrypting/server-side key exchange: {}",
                  gssex.getMessage());
            throw new XrootdException(kGSErrError,
                  "Error in server-side cryptographic " +
                        "operations.");
        }
    }

    @Override
    public boolean isFinished(BucketData data) {
        return ((hasProxy || !clientCanSignRequest) && kXGC_cert == data.getStep())
              || kXGC_sigpxy == data.getStep();
    }

    @Override
    protected String getSyncCipherMode() {
        return SYNC_CIPHER_MODE_UNPADDED;
    }

    /**
     * Processes the new kXRS_puk bucket in order to use the client public key
     * to decrypt the signed DH parameters.
     */
    private PublicKey extractClientPublicKey(Map<BucketType, GSIBucket> buckets)
          throws NoSuchProviderException, NoSuchAlgorithmException,
          InvalidKeySpecException {
        StringBucket pukBucket = (StringBucket) buckets.get(kXRS_puk);
        LOGGER.debug("Length of kXRS_puk bucket content: {}, size {}.",
              pukBucket.getContent().length(),
              pukBucket.getSize());

        byte[] base64 = CertUtil.fromPEM(pukBucket.getContent(),
              PUBLIC_KEY_HEADER,
              PUBLIC_KEY_FOOTER);
        LOGGER.debug("resulting base64 byte array length {}.",
              base64.length);

        KeyFactory keyfac = KeyFactory.getInstance(PUBLIC_KEY_ALGORITHM, "BC");

        PublicKey key = keyfac.generatePublic(new X509EncodedKeySpec(base64));
        if (key instanceof RSAPublicKey) {
            LOGGER.debug("RSA modulus lenghth: {}.", ((RSAPublicKey) key).getModulus().bitLength());
        }
        return key;
    }

    private AuthenticationResponse getSigPxyResponse(X509Certificate[] certChain,
          AuthenticationRequest request,
          NestedBucketBuffer mainBucket)
          throws XrootdException, NoSuchProviderException,
          InvalidKeyException, NoSuchAlgorithmException,
          NoSuchPaddingException, IllegalBlockSizeException,
          InvalidAlgorithmParameterException, BadPaddingException,
          IOException {
        String csr = credentialManager.prepareSerializedProxyRequest(certChain);

        PEMCredential credential = credentialManager.getHostCredential();
        rsaSession.initializeForEncryption(credential.getKey());
        GSIBucket main = postProcessMainBucket(mainBucket.getNestedBuckets(),
              Optional.of(csr),
              kXGS_pxyreq);

        GSIBucketContainer responseBuckets
              = new ProxyRequestResponse(main,
              CRYPTO_MODE)
              .buildContainer();

        BucketSerializer serializer = new BucketSerializerBuilder()
              .withStreamId(request.getStreamId())
              .withRequestId(kXR_authmore)
              .withProtocol(PROTOCOL)
              .withStep(kXGS_pxyreq)
              .withStepName(getServerStep(kXGS_pxyreq))
              .withBuckets(responseBuckets.getBuckets())
              .withTitle("//               Authentication Response")
              .build();

        return new AuthenticationResponse(request,
              kXR_authmore,
              getLengthForRequest(responseBuckets),
              serializer);
    }
}
