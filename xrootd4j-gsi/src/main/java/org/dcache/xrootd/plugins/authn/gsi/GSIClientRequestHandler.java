/**
 * Copyright (C) 2011-2021 dCache.org <support@dcache.org>
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

import eu.emi.security.authn.x509.X509Credential;
import io.netty.channel.ChannelHandlerContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.Map;
import java.util.Optional;

import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.plugins.authn.gsi.GSIBucketUtils.BucketData;
import org.dcache.xrootd.plugins.authn.gsi.GSIBucketUtils.BucketSerializer;
import org.dcache.xrootd.plugins.authn.gsi.GSIBucketUtils.BucketSerializerBuilder;
import org.dcache.xrootd.security.SigningPolicy;
import org.dcache.xrootd.security.TLSSessionInfo;
import org.dcache.xrootd.security.XrootdSecurityProtocol.*;
import org.dcache.xrootd.tpc.TpcSigverRequestEncoder;
import org.dcache.xrootd.tpc.XrootdTpcClient;
import org.dcache.xrootd.tpc.protocol.messages.InboundAuthenticationResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundErrorResponse;
import org.dcache.xrootd.tpc.protocol.messages.OutboundAuthenticationRequest;

import static org.dcache.xrootd.plugins.authn.gsi.GSIBucketUtils.getLengthForRequest;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_DecryptErr;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_IOError;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_auth;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType.*;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.*;

public abstract class GSIClientRequestHandler extends GSIRequestHandler
{
    protected static Logger LOGGER
                    = LoggerFactory.getLogger(GSIClientRequestHandler.class);

    protected class CertRequestBuckets extends GSIBucketContainerBuilder
    {
        private StringBucket       cryptoBucket;
        private UnsignedIntBucket  versionBucket;
        private StringBucket       issuerBucket;
        private UnsignedIntBucket  optionBucket;
        private NestedBucketBuffer mainBucket;

        public CertRequestBuckets(String rtag, Optional<Integer> opts)
                        throws XrootdException {
            Map<BucketType, GSIBucket> nestedBuckets
                            = new EnumMap<>(BucketType.class);
            StringBucket randomTagBucket = new StringBucket(kXRS_rtag, rtag);
            nestedBuckets.put(randomTagBucket.getType(), randomTagBucket);
            mainBucket = new NestedBucketBuffer(kXRS_main,
                                                PROTOCOL,
                                                kXGC_certreq,
                                                nestedBuckets);
            cryptoBucket = new StringBucket(kXRS_cryptomod, CRYPTO_MODE);
            versionBucket = new UnsignedIntBucket(kXRS_version,
                                                  getProtocolVersion());
            issuerBucket = new StringBucket(kXRS_issuer_hash,
                                            credentialManager.getIssuerHashes());
            if (opts.isPresent()) {
                optionBucket = new UnsignedIntBucket(kXRS_clnt_opts, opts.get());
            }
        }

        @Override
        public GSIBucketContainer buildContainer() {
            return GSIBucketContainerBuilder.build(cryptoBucket, versionBucket,
                                                   issuerBucket, mainBucket,
                                                   optionBucket);
        }
    }

    protected class CertResponseBuckets extends GSIBucketContainerBuilder
    {
        GSIBucket mainBucket;
        RawBucket dhParamsBucket;
        StringBucket cipherBucket;
        StringBucket digestBucket;
        StringBucket publicKeyBucket;
        StringBucket userNameBucket;

        public CertResponseBuckets(GSIBucket mainBucket,
                                   byte[] dhParams,
                                   BucketType dhParamType,
                                   Optional<String> publicKeyPem,
                                   Optional<String>userName,
                                   String selectedCipher,
                                   String selectedDigest)
        {
            this.mainBucket = mainBucket;

            /*
             * add params
             */
            dhParamsBucket = new RawBucket(dhParamType, dhParams);
            cipherBucket = new StringBucket(kXRS_cipher_alg, selectedCipher);
            digestBucket = new StringBucket(kXRS_md_alg, selectedDigest);

            if (publicKeyPem.isPresent()) {
                publicKeyBucket = new StringBucket(kXRS_puk, publicKeyPem.get());
            }

            if (userName.isPresent()) {
                userNameBucket = new StringBucket(kXRS_user, userName.get());
            }
        }

        @Override
        public GSIBucketContainer buildContainer() {
            return build(mainBucket, cipherBucket, digestBucket,
                         dhParamsBucket, publicKeyBucket, userNameBucket);
        }
    }

    protected final XrootdTpcClient client;

    protected GSIClientRequestHandler(GSICredentialManager credentialManager,
                                      XrootdTpcClient client) {
        super(credentialManager);
        this.client = client;
    }

    /**
     * Handle certreq step.  This code is the same between pre-4.9 and 4.9+.
     *
     * After being told by the server that authentication is required,
     * the client initiates the handshake.
     *
     * First, we check the parsed protocol to make sure that the
     * ca identities are recognized.
     *
     * Next, we build a request containing the kXRS_rtag and
     * send it to the server to be signed.
     */
    public OutboundAuthenticationRequest handleCertReqStep()
                    throws XrootdException
    {
        loadClientCredential();

        validateCryptoMode(((Optional<String>)client
                                .getAuthnContext()
                                .get("encryption"))
                             .orElse(""));

        String caIdentities = ((Optional<String>)client
                        .getAuthnContext()
                        .get("caIdentities"))
                        .orElse("");

        credentialManager.checkCaIdentities(caIdentities.split("[|]"));

        challenge = GSIRequestHandler.generateChallengeString();

        GSIBucketContainer container
                        = new CertRequestBuckets(challenge,
                                                 getClientOpts()).buildContainer();

        BucketSerializer serializer = new BucketSerializerBuilder()
                        .withStreamId(client.getStreamId())
                        .withRequestId(kXR_auth)
                        .withProtocol(PROTOCOL)
                        .withStep(kXGC_certreq)
                        .withStepName(getClientStep(kXGC_certreq))
                        .withBuckets(container.getBuckets())
                        .withTitle("//           Outbound Authentication Request")
                        .build();

        return new OutboundAuthenticationRequest(client.getStreamId(),
                                                 PROTOCOL,
                                                 getLengthForRequest(container),
                                                 serializer);
    }

    public abstract OutboundAuthenticationRequest
        handleCertStep(InboundAuthenticationResponse response,
                       BucketData data,
                       ChannelHandlerContext ctx)
                    throws XrootdException;

    protected Optional<TpcSigverRequestEncoder> getSigverEncoder(XrootdTpcClient client)
    {
        SigningPolicy signingPolicy = client.getSigningPolicy();
        TLSSessionInfo tlsSessionInfo = client.getTlsSessionInfo();
        LOGGER.debug("Getting (optional) signed hash verification encoder, "
                                     + "signing is on? {}; tls ? {}.",
                     signingPolicy.isSigningOn(), tlsSessionInfo.getClientTls());
        TpcSigverRequestEncoder sigverRequestEncoder = null;
        if (!tlsSessionInfo.clientUsesTls() && signingPolicy.isSigningOn()) {
            sigverRequestEncoder = new TpcSigverRequestEncoder(bufferHandler,
                                                               signingPolicy);
        }
        return Optional.ofNullable(sigverRequestEncoder);
    }

    protected X509Certificate validateCertificate(Map<BucketType, GSIBucket> bucketMap)
                    throws IOException, GeneralSecurityException,
                    XrootdException {
        X509Certificate[] chain = processRSAVerification(bucketMap,
                                                         Optional.empty());
        X509Certificate serverCert = chain[0];
        GSICredentialManager.checkIdentity(serverCert, client.getInfo().getSrcHost());
        return serverCert;
    }

    protected String validateCiphers(Map<BucketType, GSIBucket> bucketMap)
                    throws XrootdException
    {
        StringBucket cipherBucket
                        = (StringBucket) bucketMap.get(kXRS_cipher_alg);

        return validateCiphers(cipherBucket.getContent().split("[:]"));
    }

    protected String validateDigests(Map<BucketType, GSIBucket> bucketMap)
                    throws XrootdException
    {
        StringBucket digestBucket
                        = (StringBucket) bucketMap.get(kXRS_md_alg);

        return validateDigests(digestBucket.getContent().split("[:]"));
    }

    /**
     * The processing of this step differs between versions only in these details:
     *
     * (A) the bucket containing DH params:
     *          pre-4.9 = kXRS_puk, 4.9 = kXRS_cipher
     * (B) DH parameters are signed using the private key:
     *          pre-4.9 no, 4.9 yes
     * (C) the public key of the client is included in a separate bucket:
     *          pre-4.9 no, 4.9 in kXRS_puk
     * (D) a username bucket is included
     *          pre-4.9 no, 4.9 yes
     *
     *  Otherwise, all the following must be done:
     *
     *  -  validate cipher and digest
     *  -  extract and validate the server certificate
     *  -  verify the rtag challenge sent previously
     *  -  finalize the dh session from the dh params sent by server
     *  -  create the main bucket with signed challenge, new challenge
     *     and serialized certificate of client
     *  -  add buckets for cipher, digest, dhParams, and optionally publicKey
     *     and username.
     */
    protected OutboundAuthenticationRequest
        handleCertStep(InboundAuthenticationResponse response,
                       BucketData data,
                       ChannelHandlerContext ctx,
                       BucketType dhParamBucket,
                       boolean signDhParams,
                       Optional<String> publicKeyPem,
                       Optional<String> userName) throws XrootdException
    {
        try {
            Map<BucketType, GSIBucket> bucketMap = data.getBucketMap();
            String selectedCipher = validateCiphers(bucketMap);
            String selectedDigest = validateDigests(bucketMap);
            X509Certificate serverCert = validateCertificate(bucketMap);
            rsaSession.initializeForDecryption(serverCert.getPublicKey());
            verifySignedRTag(bucketMap);

            dhSession = new DHSession(false, findSessionIVLen(selectedCipher));
            dhSession.setPaddedKey(usePadded());
            finalizeSessionKey(bucketMap, dhParamBucket);

            Optional<TpcSigverRequestEncoder> encoder = getSigverEncoder(client);
            if (encoder.isPresent()) {
                /*
                 * Insert sigver encoder into pipeline.  Added after the encoder,
                 * but for outbound processing, it gets called before the encoder.
                 */
                ctx.pipeline()
                   .addAfter("encoder", "sigverEncoder", encoder.get());
            }

            X509Credential clientCredential = getClientCredential();
            X509Certificate[] chain = clientCredential.getCertificateChain();
            String serializedCert = CertUtil.chainToPEM(Arrays.asList(chain));
            rsaSession.initializeForEncryption(clientCredential.getKey());

            GSIBucket mainBucket
                            = postProcessMainBucket(bucketMap,
                                                    Optional.of(serializedCert),
                                                    kXGC_cert);

            GSIBucketContainer container =
                            new CertResponseBuckets(mainBucket,
                                                    dhParams(signDhParams),
                                                    dhParamBucket,
                                                    publicKeyPem,
                                                    userName,
                                                    selectedCipher,
                                                    selectedDigest)
                                            .buildContainer();

            BucketSerializer serializer = new BucketSerializerBuilder()
                            .withStreamId(client.getStreamId())
                            .withRequestId(kXR_auth)
                            .withProtocol(PROTOCOL)
                            .withStep(kXGC_cert)
                            .withStepName(getClientStep(kXGC_cert))
                            .withBuckets(container.getBuckets())
                            .withTitle("//           Outbound Authentication Request")
                            .build();

            return new OutboundAuthenticationRequest(response.getStreamId(),
                                                     PROTOCOL,
                                                     getLengthForRequest(container),
                                                     serializer);
        } catch (IOException e) {
            LOGGER.error("Problems during cert step {}." +
                                         e.getMessage() == null ? e.getClass().getName() :
                                         e.getMessage());
            throw new XrootdException(kXR_IOError,
                                      "Internal error occurred during cert step.");
        } catch (InvalidKeyException e) {
            LOGGER.error("The key negotiated by DH key exchange appears to " +
                                         "be invalid: {}", e.getMessage());
            throw new XrootdException(kXR_DecryptErr,
                                      "Could not decrypt server " +
                                                      "information with negotiated key.");
        } catch (GeneralSecurityException e) {
            LOGGER.error("Cryptographic issues encountered during cert step: {}",
                         e.getMessage());
            throw new XrootdException(kGSErrError,
                                      "Could not complete cert step: an error "
                                                      + "occurred during "
                                                      + "cryptographic operations.");
        }
    }

    protected abstract X509Credential getClientCredential();

    protected abstract Optional<Integer> getClientOpts();

    protected abstract void handleAuthenticationError(InboundErrorResponse response)
                    throws XrootdException;

    protected abstract void loadClientCredential() throws XrootdException;

    protected abstract boolean usePadded();
}
