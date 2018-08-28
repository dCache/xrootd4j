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
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelId;
import io.netty.channel.ChannelInboundHandler;

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
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.plugins.authn.gsi.BaseGSIAuthenticationHandler.*;
import org.dcache.xrootd.security.NestedBucketBuffer;
import org.dcache.xrootd.security.RawBucket;
import org.dcache.xrootd.security.StringBucket;
import org.dcache.xrootd.security.XrootdBucket;
import org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType;
import org.dcache.xrootd.tpc.AbstractClientRequestHandler;
import org.dcache.xrootd.tpc.XrootdTpcClient;
import org.dcache.xrootd.tpc.XrootdTpcInfo;
import org.dcache.xrootd.tpc.protocol.messages.AbstractXrootdInboundResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundAttnResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundAuthenticationResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundLoginResponse;
import org.dcache.xrootd.tpc.protocol.messages.OutboundAuthenticationRequest;

import static io.netty.channel.ChannelFutureListener.FIRE_EXCEPTION_ON_FAILURE;
import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.dcache.xrootd.plugins.authn.gsi.BaseGSIAuthenticationHandler.PROTOCOL_VERSION;
import static org.dcache.xrootd.plugins.authn.gsi.BaseGSIAuthenticationHandler.*;
import static org.dcache.xrootd.plugins.authn.gsi.GSIAuthenticationHandler.CRYPTO_MODE;
import static org.dcache.xrootd.plugins.authn.gsi.GSIAuthenticationHandler.PROTOCOL;
import static org.dcache.xrootd.protocol.XrootdProtocol.*;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType.*;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.kXGC_cert;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.kXGC_certreq;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.kXGS_cert;

/**
 *  <p>Client-side handler mirroring the server-side GSIAuthenticationHandler.
 *     Added to the channel pipeline to handle protocol and auth requests
 *     and responses.</p>
 */
public class GSIClientAuthenticationHandler extends
                AbstractClientRequestHandler implements ChannelInboundHandler
{
    static XrootdBucketContainer build(XrootdBucket ... buckets)
    {
        int responseLength = 0;
        List<XrootdBucket> responseList = new ArrayList<>();
        for (XrootdBucket bucket: buckets) {
            responseList.add(bucket);
            responseLength += bucket.getSize();
        }
        return new XrootdBucketContainer(responseList, responseLength);
    }

    interface BucketContainerBuilder
    {
        XrootdBucketContainer buildContainer();
    }

    class InboundResponseBuckets
    {
        private String srcHost;
        private byte[] signedChallenge;
        private byte[] puk;
        private String hostProxyCert;
        private String selectedCipher;
        private String selectedDigest;

        private RawBucket    signedRTagBucket;
        private StringBucket randomTagBucket;
        private StringBucket dhPublicBucket;
        private StringBucket cipherBucket;
        private StringBucket digestBucket;
        private StringBucket serverX509Bucket;
        private X509Certificate serverCert;

        private DHSession session;
        private String rtag;
        private Cipher challengeCipher;

        InboundResponseBuckets(InboundAuthenticationResponse response,
                               XrootdTpcClient client)
                        throws GeneralSecurityException
        {
            srcHost = client.getInfo().getSrcHost();
            rtag = (String)client.getAuthnContext().get("rtag");

            if (!response.getProtocol().equals(PROTOCOL)) {
                throw new GeneralSecurityException("server replied with incorrect "
                                                                   + "protocol: " +
                                                                   response.getProtocol());
            }

            if (response.getServerStep() != kXGS_cert) {
                throw new GeneralSecurityException("server replied with incorrect "
                                                                   + "step: " +
                                                                   response.getServerStep());
            }

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
            X509Certificate[] chain = handler.credential.getCertificateChain();
            for (X509Certificate cert : chain) {
                cert.getEncoded();
                builder.append(CertUtil.certToPEM(cert));
            }

            hostProxyCert = builder.toString();
        }

        void signChallenge() throws InvalidKeyException, BadPaddingException,
                        IllegalBlockSizeException, IOException
        {
            challengeCipher.init(Cipher.ENCRYPT_MODE,
                                         handler.credential.getKey());
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
            handler.validator.validate(proxyCertChain);

            if (serverCert.getSubjectDN().getName().contains(srcHost) ||
                CERT_CHECKER.checkMatching(srcHost, serverCert)) {
                return;
            }

            error = "The name of the source server does not match any subject "
                            + "name of the received credential.";
            throw new GeneralSecurityException(error);
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

    class OutboundRequestBuckets implements BucketContainerBuilder
    {
        private StringBucket cryptoBucket;
        private StringBucket versionBucket;
        private StringBucket issuerBucket;
        private NestedBucketBuffer mainBucket;

        OutboundRequestBuckets(String rtag) throws XrootdException {
            Map<BucketType, XrootdBucket> nestedBuckets
                            = new EnumMap<>(BucketType.class);
            StringBucket randomTagBucket = new StringBucket(kXRS_rtag, rtag);
            nestedBuckets.put(randomTagBucket.getType(), randomTagBucket);
            mainBucket = new NestedBucketBuffer(kXRS_main, PROTOCOL, kXGC_certreq,
                                                nestedBuckets);
            cryptoBucket = new StringBucket(kXRS_cryptomod, CRYPTO_MODE);
            versionBucket = new StringBucket(kXRS_version,
                                             PROTOCOL_VERSION.substring(0, 4));
            issuerBucket = new StringBucket(kXRS_issuer_hash, issuerHashes);
        }

        @Override
        public XrootdBucketContainer buildContainer() {
            return build(cryptoBucket, versionBucket, issuerBucket, mainBucket);
        }
    }

    class OutboundResponseBuckets implements BucketContainerBuilder
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
                                                       buckets.hostProxyCert);
            RawBucket signedTagBucket = new RawBucket(kXRS_signed_rtag,
                                                      buckets.signedChallenge);

            /*
             *  Construct the main bucket with the 8 byte protocol-step header,
             *  but without bucket type header.
             */
            ByteBuf buffer = ctx.alloc().buffer();
            byte[] bytes = BaseGSIAuthenticationHandler.PROTOCOL.getBytes(US_ASCII);
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
        public XrootdBucketContainer buildContainer() {
            return build(encryptedBucket, cipherBucket, digestBucket, pukBucket);
        }
    }

    private BaseGSIAuthenticationHandler handler;
    private String                       issuerHashes;

    public GSIClientAuthenticationHandler(X509Credential proxyCredential,
                                          X509CertChainValidator validator,
                                          String certDir,
                                          String issuerHashes)
    {
        handler = new BaseGSIAuthenticationHandler(proxyCredential,
                                                   validator,
                                                   certDir);
        this.issuerHashes = issuerHashes;
    }

    @Override
    protected void doOnAsynResponse(ChannelHandlerContext ctx,
                                    InboundAttnResponse response)
    {
        switch (response.getRequestId()) {
            case kXR_auth:
                try {
                    sendAuthenticationRequest(ctx);
                } catch (XrootdException e) {
                    exceptionCaught(ctx, e);
                }
                break;
            default:
                super.doOnAsynResponse(ctx, response);
        }
    }

    @Override
    protected void doOnAuthenticationResponse(ChannelHandlerContext ctx,
                                              InboundAuthenticationResponse response)
    {
        ChannelId id = ctx.channel().id();
        int status = response.getStatus();
        int streamId = client.getStreamId();
        XrootdTpcInfo tpcInfo = client.getInfo();
        switch (status) {
            case kXR_ok:
                LOGGER.trace("Authentication to {}, channel {}, stream {}, "
                                             + "sessionId {} succeeded; "
                                             + "passing to next handler.",
                             tpcInfo.getSrc(),
                             id,
                             streamId,
                             client.getSessionId());
                ctx.fireChannelRead(response);
                break;
            case kXR_authmore:
                LOGGER.trace("Authentication to {}, channel {}, stream {}, "
                                             + "sessionId {}, "
                                             + "proceeding to next step.",
                             tpcInfo.getSrc(),
                             id,
                             streamId,
                             client.getSessionId());
                try {
                    client.setAuthResponse(response);
                    sendAuthenticationRequest(ctx);
                } catch (XrootdException e) {
                    exceptionCaught(ctx, e);
                }
                break;
            default:
                exceptionCaught(ctx,
                                new RuntimeException("wrong status from "
                                + "authentication response: " + status));
        }
    }

    /**
     * Arriving here means login succeeded.  Check for authentication
     * requirement.
     */
    @Override
    protected void doOnLoginResponse(ChannelHandlerContext ctx,
                                     InboundLoginResponse response)
    {
        ChannelId id = ctx.channel().id();
        String sec = response.getSec();
        int streamId = client.getStreamId();
        XrootdTpcInfo tpcInfo = client.getInfo();

        if (sec == null) {
            LOGGER.trace("login to {}, channel {}, stream {}, session {}, "
                                         + "does not require "
                                         + "authentication; "
                                         + "passing to next handler in chain.",
                         tpcInfo.getSrc(),
                         id,
                         streamId,
                         client.getSessionId());
            ctx.fireChannelRead(response);
            return;
        }

        try {
            if (!isGsiRequired(sec)) {
                LOGGER.trace("login to {}, channel {}, stream {}, session {}, "
                                             + "requires a different protocol; "
                                             + "passing to next handler in chain.",
                             tpcInfo.getSrc(),
                             id,
                             streamId,
                             client.getSessionId());
                ctx.fireChannelRead(response);
                return;
            }

            parseSec(sec);
            sendAuthenticationRequest(ctx);
        } catch (XrootdException e) {
            exceptionCaught(ctx, e);
        }
    }

    @Override
    protected void doOnWaitResponse(final ChannelHandlerContext ctx,
                                    AbstractXrootdInboundResponse response)
    {
        switch (response.getRequestId()) {
            case kXR_auth:
                client.getExecutor().schedule(new Runnable() {
                                                  @Override
                                                  public void run() {
                                                      try {
                                                          sendAuthenticationRequest(ctx);
                                                      } catch (XrootdException e) {
                                                          exceptionCaught(ctx, e);
                                                      }
                                                  }
                                              }, getWaitInSeconds(response),
                                              TimeUnit.SECONDS);
                break;
            default:
                ctx.fireChannelRead(response);
        }
    }

    @Override
    protected void sendAuthenticationRequest(ChannelHandlerContext ctx)
                    throws XrootdException
    {
        ChannelId id = ctx.channel().id();
        int streamId = client.getStreamId();
        XrootdTpcInfo tpcInfo = client.getInfo();
        OutboundAuthenticationRequest request;
        InboundAuthenticationResponse previous = client.getAuthResponse();
        if (previous != null) {
            request = handleCertStep(previous, ctx);
            LOGGER.trace("sendAuthenticationRequest to {}, channel {}, "
                                         + "stream {}, step: cert.",
                         tpcInfo.getSrc(), id, streamId);
        } else {
            request = handleCertReqStep();
            LOGGER.trace("sendAuthenticationRequest to {}, channel {}, "
                                         + "stream {}, step: cert request.",
                         tpcInfo.getSrc(), id, streamId);
        }

        client.setExpectedResponse(kXR_auth);
        client.setAuthResponse(null);
        ctx.writeAndFlush(request, ctx.newPromise())
           .addListener(FIRE_EXCEPTION_ON_FAILURE);
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
    private OutboundAuthenticationRequest handleCertReqStep()
                    throws XrootdException
    {
        String encryption = (String)client.getAuthnContext().get("encryption");
        if (!encryption.equalsIgnoreCase(CRYPTO_MODE)) {
            throw new XrootdException(kXR_error,
                                      "handler does not support "
                                                      + encryption);
        }

        String[] caIdentities = (String[])client.getAuthnContext().get("caIdentities");
        handler.checkCaIdentities(caIdentities);
        String version = (String)client.getAuthnContext().get("version");
        handler.checkVersion(version);
        String rtag = handler.generateChallengeString();
        client.getAuthnContext().put("rtag", rtag);

        XrootdBucketContainer container
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
    private OutboundAuthenticationRequest handleCertStep(InboundAuthenticationResponse response,
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
            DHEncrypter encrypter = new DHEncrypter(inbound.session,
                                                    SERVER_SYNC_CIPHER_MODE,
                                                    SERVER_SYNC_CIPHER_NAME,
                                                    SERVER_SYNC_CIPHER_BLOCKSIZE);
            GSISigverRequestHandler sigverRequestHandler =
                            new GSISigverRequestHandler(encrypter, client);
            client.setSigverRequestHandler(sigverRequestHandler);

            XrootdBucketContainer container =
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

    private boolean isGsiRequired(String sec) throws XrootdException
    {
        if (!sec.startsWith("&P=")) {
            throw new XrootdException(kXR_error, "Malformed 'sec': " + sec);
        }
        String protocol = sec.substring(3, sec.indexOf(","));
        return PROTOCOL.equals(protocol);
    }

    private void parseSec(String sec) throws XrootdException
    {
        int index = sec.indexOf(",");
        if (index == -1 || index == sec.length() - 1) {
            throw new XrootdException(kXR_error, "Invalid 'sec': " + sec);
        }

        String[] parts = sec.substring(index + 1).split("[,]");
        if (parts.length != 3) {
            throw new XrootdException(kXR_error, "Invalid 'sec': " + sec);
        }

        for (String part : parts) {
            String[] keyVal = part.split("[:]");
            switch (keyVal[0].toLowerCase()) {
                case "v":
                    client.getAuthnContext().put("version", keyVal[1]);
                    break;
                case "c":
                    client.getAuthnContext().put("encryption", keyVal[1]);
                    break;
                case "ca":
                    client.getAuthnContext().put("caIdentities",
                                                 keyVal[1].split("[|]"));
                    break;
            }
        }
    }
}
