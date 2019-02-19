/**
 * Copyright (C) 2011-2019 dCache.org <support@dcache.org>
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
package org.dcache.xrootd.plugins.authn.gsi.pre49;

import eu.emi.security.authn.x509.impl.CertificateUtils;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.EnumMap;
import java.util.Map;
import java.util.Optional;

import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.plugins.authn.gsi.CertUtil;
import org.dcache.xrootd.plugins.authn.gsi.DHBufferHandler;
import org.dcache.xrootd.plugins.authn.gsi.DHSession;
import org.dcache.xrootd.plugins.authn.gsi.GSIBucketContainer;
import org.dcache.xrootd.plugins.authn.gsi.GSIBucketContainerBuilder;
import org.dcache.xrootd.plugins.authn.gsi.GSIClientRequestHandler;
import org.dcache.xrootd.plugins.authn.gsi.GSICredentialManager;
import org.dcache.xrootd.plugins.authn.gsi.GSIRequestHandler;
import org.dcache.xrootd.security.BufferEncrypter;
import org.dcache.xrootd.security.NestedBucketBuffer;
import org.dcache.xrootd.security.RawBucket;
import org.dcache.xrootd.security.SigningPolicy;
import org.dcache.xrootd.security.StringBucket;
import org.dcache.xrootd.security.UnsignedIntBucket;
import org.dcache.xrootd.security.XrootdBucket;
import org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType;
import org.dcache.xrootd.tpc.TpcSigverRequestEncoder;
import org.dcache.xrootd.tpc.XrootdTpcClient;
import org.dcache.xrootd.tpc.protocol.messages.InboundAuthenticationResponse;
import org.dcache.xrootd.tpc.protocol.messages.OutboundAuthenticationRequest;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_InvalidRequest;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_ServerError;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_error;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType.*;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.kGSErrBadOpt;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.kXGC_cert;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.kXGC_certreq;

public class GSIPre49ClientRequestHandler extends GSIClientRequestHandler
{
    class InboundResponseBuckets
    {
        private String srcHost;
        private byte[] signedChallenge;
        private byte[] puk;
        private String proxyCert;
        private String selectedCipher;
        private String selectedDigest;

        private RawBucket       signedRTagBucket;
        private StringBucket    randomTagBucket;
        private StringBucket    dhPublicBucket;
        private StringBucket    cipherBucket;
        private StringBucket    digestBucket;
        private StringBucket    serverX509Bucket;
        private X509Certificate serverCert;

        private DHSession session;
        private String    rtag;
        private Cipher    challengeCipher;

        InboundResponseBuckets(InboundAuthenticationResponse response,
                               XrootdTpcClient client)
                        throws GeneralSecurityException
        {
            srcHost = client.getInfo().getSrcHost();
            rtag = (String)client.getAuthnContext().get("rtag");
            Map<BucketType, XrootdBucket> receivedBuckets = response.getBuckets();
            dhPublicBucket = (StringBucket)receivedBuckets.get(kXRS_puk);
            cipherBucket = (StringBucket)receivedBuckets.get(kXRS_cipher_alg);
            digestBucket = (StringBucket)receivedBuckets.get(kXRS_md_alg);
            serverX509Bucket = (StringBucket)receivedBuckets.get(kXRS_x509);
            signedRTagBucket = (RawBucket)receivedBuckets.get(kXRS_signed_rtag);
            randomTagBucket = (StringBucket)receivedBuckets.get(kXRS_rtag);
        }

        void finalizeDHSessionKey()
                        throws IOException, GeneralSecurityException,
                        XrootdException
        {
            session = new DHSession(false);
            session.finaliseKeyAgreement(dhPublicBucket.getContent());
            puk = session.getEncodedDHMaterial().getBytes();
        }

        void encodeHostCerts() throws CertificateEncodingException
        {
            StringBuilder builder = new StringBuilder();
            X509Certificate[] chain = credentialManager.getProxy()
                                                       .getCertificateChain();
            for (X509Certificate cert : chain) {
                cert.getEncoded();
                builder.append(CertUtil.certToPEM(cert));
            }

            proxyCert = builder.toString();
        }

        void signChallenge() throws InvalidKeyException, BadPaddingException,
                        IllegalBlockSizeException, IOException
        {
            challengeCipher.init(Cipher.ENCRYPT_MODE,
                                 credentialManager.getProxy().getKey());
            String serverRtag = randomTagBucket.getContent();
            challengeCipher.update(serverRtag.getBytes());
            signedChallenge = challengeCipher.doFinal();
        }

        void validateCertificate() throws IOException, GeneralSecurityException
        {
            String error;
            byte[] clientX509 = serverX509Bucket.getContent().getBytes(US_ASCII);

            X509Certificate[] proxyCertChain = CertificateUtils
                            .loadCertificateChain(new ByteArrayInputStream(clientX509),
                                                  CertificateUtils.Encoding.PEM);
            if (proxyCertChain.length == 0) {
                error = "Could not parse server certificate from input stream!";
                throw new GeneralSecurityException(error);
            }

            serverCert = proxyCertChain[0];
            credentialManager.getValidator().validate(proxyCertChain);
            GSICredentialManager.checkIdentity(serverCert, srcHost);
        }

        void validateCiphers() throws XrootdException
        {
            String[] algorithms = cipherBucket.getContent().split("[:]");
            for (String algorithm: algorithms) {
                if (SUPPORTED_CIPHER_ALGORITHMS.contains(algorithm)) {
                    selectedCipher = algorithm;
                    break;
                }
            }

            if (selectedCipher == null) {
                throw new XrootdException(kXR_error, "all server ciphers are "
                                + "unsupported: " + cipherBucket.getContent());
            }
        }

        void validateDigests() throws XrootdException
        {
            String[] digests = digestBucket.getContent().split("[:]");
            for (String digest: digests) {
                if (SUPPORTED_DIGESTS.contains(digest)) {
                    selectedDigest = digest;
                    break;
                }
            }

            if (selectedDigest == null) {
                throw new XrootdException(kXR_error, "all server digests are "
                                + "unsupported: " + digestBucket.getContent());
            }
        }

        void validateSignedChallenge()
                        throws XrootdException, InvalidKeyException,
                        NoSuchPaddingException, NoSuchAlgorithmException,
                        NoSuchProviderException, BadPaddingException,
                        IllegalBlockSizeException
        {
            challengeCipher = Cipher.getInstance(SERVER_ASYNC_CIPHER_MODE, "BC");
            challengeCipher.init(Cipher.DECRYPT_MODE, serverCert.getPublicKey());

            byte[] signedRTag = signedRTagBucket.getContent();

            byte[] rTag = challengeCipher.doFinal(signedRTag);
            String rTagString = new String(rTag, US_ASCII);

            if (!rtag.equals(rTagString)) {
                LOGGER.error("The challenge is {}, the serialized rTag is {}." +
                                             "signature of challenge tag "
                                             + "has been proven wrong!!",
                             rtag, rTagString);
                throw new XrootdException(kXR_InvalidRequest,
                                          "Client did not present correct " +
                                                          "challenge response!");
            }

            LOGGER.trace("signature of challenge tag ok. Challenge: " +
                                         "{}, rTagString: {}",
                         rtag, rTagString);
        }
    }

    class OutboundRequestBuckets extends GSIBucketContainerBuilder
    {
        private StringBucket       cryptoBucket;
        private UnsignedIntBucket  versionBucket;
        private StringBucket       issuerBucket;
        private NestedBucketBuffer mainBucket;

        OutboundRequestBuckets(String rtag) throws XrootdException {
            Map<BucketType, XrootdBucket> nestedBuckets
                            = new EnumMap<>(BucketType.class);
            StringBucket randomTagBucket = new StringBucket(kXRS_rtag, rtag);
            nestedBuckets.put(randomTagBucket.getType(), randomTagBucket);
            mainBucket = new NestedBucketBuffer(kXRS_main, PROTOCOL, kXGC_certreq,
                                                nestedBuckets);
            cryptoBucket = new StringBucket(kXRS_cryptomod, CRYPTO_MODE);
            versionBucket = new UnsignedIntBucket(kXRS_version, getProtocolVersion());
            issuerBucket = new StringBucket(kXRS_issuer_hash,
                                            credentialManager.getClientCredIssuerHashes());
        }

        @Override
        public GSIBucketContainer buildContainer() {
            return GSIBucketContainerBuilder.build(cryptoBucket, versionBucket,
                                                   issuerBucket, mainBucket);
        }
    }

    class OutboundResponseBuckets extends GSIBucketContainerBuilder
    {
        RawBucket encryptedBucket;
        RawBucket pukBucket;
        StringBucket cipherBucket;
        StringBucket digestBucket;

        OutboundResponseBuckets(InboundResponseBuckets buckets,
                                ChannelHandlerContext ctx)
                        throws NoSuchPaddingException,
                        InvalidAlgorithmParameterException,
                        NoSuchAlgorithmException, IllegalBlockSizeException,
                        BadPaddingException, NoSuchProviderException,
                        InvalidKeyException
        {
            pukBucket = new RawBucket(kXRS_puk, buckets.puk);
            cipherBucket = new StringBucket(kXRS_cipher_alg, buckets.selectedCipher);
            digestBucket = new StringBucket(kXRS_md_alg, buckets.selectedDigest);
            StringBucket x509Bucket = new StringBucket(kXRS_x509,
                                                       buckets.proxyCert);
            RawBucket signedTagBucket = new RawBucket(kXRS_signed_rtag,
                                                      buckets.signedChallenge);

            /*
             *  Construct the main bucket with the 8 byte protocol-step header,
             *  but without bucket type header.
             */
            ByteBuf buffer = ctx.alloc().buffer();
            byte[] bytes = PROTOCOL.getBytes(US_ASCII);
            buffer.writeBytes(bytes);
            buffer.writeZero(4 - bytes.length);
            buffer.writeInt(kXGC_cert);
            signedTagBucket.serialize(buffer);
            x509Bucket.serialize(buffer);
            buffer.writeInt(BucketType.kXRS_none.getCode());
            byte [] raw = new byte[buffer.readableBytes()];
            buffer.getBytes(0, raw);
            buffer.release();

            /*
             *  DH session key should be finalized by this time.
             */
            byte [] encrypted = buckets.session.encrypt(SERVER_SYNC_CIPHER_MODE,
                                                        SERVER_SYNC_CIPHER_NAME,
                                                        SERVER_SYNC_CIPHER_BLOCKSIZE,
                                                        raw);
            encryptedBucket = new RawBucket(kXRS_main, encrypted);
        }

        @Override
        public GSIBucketContainer buildContainer() {
            return build(encryptedBucket, cipherBucket, digestBucket, pukBucket);
        }
    }

    public GSIPre49ClientRequestHandler(GSICredentialManager credentialManager,
                                        XrootdTpcClient client)
    {
        super(credentialManager, client);
    }

    @Override
    public int getProtocolVersion()
    {
        return PROTO_PRE_DELEGATION;
    }

    /**
     * After being told by the server that authentication is required,
     * the client initiates the handshake.
     *
     * First, we check the parsed protocol to make sure that the
     * ca identities are recognized.
     *
     * Next, we build a request containing the 8-byte kXRS_rtag and
     * send it to the server to be signed.
     */
    public OutboundAuthenticationRequest handleCertReqStep()
                    throws XrootdException
    {
        String encryption = ((Optional<String>)client
                        .getAuthnContext()
                        .get("encryption"))
                        .orElse("");
        if (!encryption.equalsIgnoreCase(CRYPTO_MODE)) {
            throw new XrootdException(kXR_error, encryption + " not supported.");
        }

        String caIdentities = ((Optional<String>)client
                        .getAuthnContext()
                        .get("caIdentities"))
                        .orElse("");
        credentialManager.checkCaIdentities(caIdentities.split("[|]"));
        String rtag = GSIRequestHandler.generateChallengeString();
        client.getAuthnContext().put("rtag", rtag);

        GSIBucketContainer container
                        = new OutboundRequestBuckets(rtag).buildContainer();

        return new OutboundAuthenticationRequest(client.getStreamId(),
                                                 container.getSize(),
                                                 PROTOCOL,
                                                 kXGC_certreq,
                                                 container.getBuckets());
    }

    /**
     * The challenge cipher sent in the kXR_certreq step is sent back.
     *
     * The cipher is signed by the source's private key. We use the
     * included public key to verify it.
     *
     * Then we sign the included challenge from the server, and
     * return it with our host cert (public key).
     */
    public OutboundAuthenticationRequest handleCertStep(InboundAuthenticationResponse response,
                                                         ChannelHandlerContext ctx)
                    throws XrootdException
    {
        try {
            InboundResponseBuckets inbound
                            = new InboundResponseBuckets(response, client);

            inbound.validateCiphers();
            inbound.validateDigests();
            inbound.validateCertificate();
            inbound.validateSignedChallenge();
            inbound.signChallenge();
            inbound.encodeHostCerts();
            inbound.finalizeDHSessionKey();

            SigningPolicy signingPolicy = client.getSigningPolicy();

            if (signingPolicy.isSigningOn()) {
                BufferEncrypter encrypter = new DHBufferHandler(inbound.session,
                                                                SERVER_SYNC_CIPHER_MODE,
                                                                SERVER_SYNC_CIPHER_NAME,
                                                                SERVER_SYNC_CIPHER_BLOCKSIZE);
                /*
                 * Insert sigver encoder into pipeline.  Added after the encoder,
                 * but for outbound processing, it gets called before the encoder.
                 */
                TpcSigverRequestEncoder sigverRequestEncoder =
                                new TpcSigverRequestEncoder(encrypter,
                                                            signingPolicy);

                ctx.pipeline().addAfter("encoder",
                                        "sigverEncoder",
                                        sigverRequestEncoder);
            }

            GSIBucketContainer container =
                            new OutboundResponseBuckets(inbound, ctx).buildContainer();

            return new OutboundAuthenticationRequest(response.getStreamId(),
                                                     container.getSize(),
                                                     PROTOCOL,
                                                     kXGC_cert,
                                                     container.getBuckets());
        } catch (IOException e) {
            LOGGER.error("Problems during cert step {}." +
                                         e.getMessage() == null ? e.getClass().getName() :
                                         e.getMessage());
            throw new XrootdException(kXR_ServerError,
                                      "Internal error occurred during cert step.");
        } catch (InvalidKeyException e) {
            LOGGER.error("The key negotiated by DH key exchange appears to " +
                                         "be invalid: {}", e.getMessage());
            throw new XrootdException(kXR_InvalidRequest,
                                      "Could not decrypt server " +
                                                      "information with negotiated key.");
        } catch (GeneralSecurityException e) {
            LOGGER.error("Cryptographic issues encountered during cert step: {}",
                         e.getMessage());
            throw new XrootdException(kXR_ServerError,
                                      "Could not complete cert step: an error "
                                                      + "occurred during "
                                                      + "cryptographic operations.");
        }
    }

    @Override
    public OutboundAuthenticationRequest
        handleSigPxyStep(InboundAuthenticationResponse response,
                         ChannelHandlerContext ctx)
                    throws XrootdException {
        throw new XrootdException(kGSErrBadOpt, "Version "
                        + getProtocolVersion()
                        + " does not support proxy delegation.");
    }
}
