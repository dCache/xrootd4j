/**
 * Copyright (C) 2011-2022 dCache.org <support@dcache.org>
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

import eu.emi.security.authn.x509.impl.PEMCredential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Optional;

import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.protocol.XrootdProtocol;
import org.dcache.xrootd.protocol.messages.AuthenticationRequest;
import org.dcache.xrootd.protocol.messages.AuthenticationResponse;
import org.dcache.xrootd.protocol.messages.XrootdResponse;
import org.dcache.xrootd.security.BufferDecrypter;
import org.dcache.xrootd.security.NestedBucketBuffer;
import org.dcache.xrootd.security.RawBucket;
import org.dcache.xrootd.security.StringBucket;
import org.dcache.xrootd.security.XrootdBucket;
import org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType;

import static org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType.*;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.kGSErrError;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.kGSErrInit;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.kXGS_cert;

public abstract class GSIServerRequestHandler extends GSIRequestHandler
{
    protected static Logger LOGGER
                = LoggerFactory.getLogger(GSIServerRequestHandler.class);

    protected class CertRequestBuckets extends GSIBucketContainerBuilder
    {
        XrootdBucket mainBucket;
        RawBucket dhPublicBucket;
        StringBucket cryptoBucket;
        StringBucket cipherBucket;
        StringBucket digestBucket;
        StringBucket hostCertBucket;

        public CertRequestBuckets(XrootdBucket mainBucket,
                                  String cryptoMode,
                                  byte [] signedDHParams,
                                  BucketType dhParamBucketType,
                                  String supportedCiphers,
                                  String supportedDigests,
                                  String hostCertificate)
        {
            this.mainBucket = mainBucket;
            cryptoBucket = new StringBucket(kXRS_cryptomod, cryptoMode);
            dhPublicBucket = new RawBucket(dhParamBucketType, signedDHParams);
            cipherBucket = new StringBucket(kXRS_cipher_alg, supportedCiphers);
            digestBucket = new StringBucket(kXRS_md_alg, supportedDigests);
            hostCertBucket = new StringBucket(kXRS_x509, hostCertificate);
        }

        @Override
        public GSIBucketContainer buildContainer() {
            return build(mainBucket, cryptoBucket, dhPublicBucket,
                         cipherBucket, digestBucket, hostCertBucket);
        }
    }

    protected final Subject              subject;

    protected GSIServerRequestHandler(Subject subject,
                                      GSICredentialManager credentialManager)
                    throws XrootdException
    {
        super(credentialManager);
        this.subject = subject;

        /*
         * Assume the normal semantics for the version, but this
         * is adjusted by the actual client response.
         */
        int sessionIVLen = getProtocolVersion() < PROTO_WITH_DELEGATION ? 0
                        : SESSION_IV_LEN;

        try {
            dhSession = new DHSession(true, sessionIVLen);
        } catch (GeneralSecurityException gssex) {
            LOGGER.error("Error setting up cryptographic classes: {}",
                         gssex.getMessage());
            throw new XrootdException(kGSErrInit,
                                      "dCache GSI module probably misconfigured.");
        }
    }

    public BufferDecrypter getDecrypter()
    {
        return bufferHandler;
    }

    public void cancelHandshake()
    {
        credentialManager.cancelOutstandingProxyRequest();
    }

    public abstract XrootdResponse<AuthenticationRequest>
        handleCertReqStep(AuthenticationRequest request)
                    throws XrootdException;

    public abstract XrootdResponse<AuthenticationRequest>
        handleCertStep(AuthenticationRequest request)
                    throws XrootdException;

    public abstract XrootdResponse<AuthenticationRequest>
        handleSigPxyStep(AuthenticationRequest request)
                    throws XrootdException;

    public abstract boolean isFinished(AuthenticationRequest request);

    /**
     * Handle the kXGC_certreq step.
     *
     * This step is basically unchanged between pre-4.9 and 4.9+ versions.
     *
     * Use host credential private key to encrypt challenge tag.  Pass
     * this along with DH parameters needed for symmetric key exchange,
     * a list of supported symmetric ciphers and digests, to the client.
     *
     * Depending on the protocol implementation, the DH-parameters
     * may or may not be signed using the RSA private key.
     *
     * @param request The received authentication request
     * @param signDHParams if true, sign using RSA private key
     * @param dhParamBucketType either kXRS_puk (pre-4.9) or kXRS_cipher (4.9+).
     * @return AuthenticationResponse with kXR_authmore
     */
    protected XrootdResponse<AuthenticationRequest>
        handleCertReqStep(AuthenticationRequest request,
                          boolean signDHParams,
                          BucketType dhParamBucketType) throws XrootdException
    {
        try {
            StringBucket bucket = (StringBucket)request.getBuckets()
                                                       .get(kXRS_cryptomod);
            validateCryptoMode(bucket.getContent());

            bucket = (StringBucket)request.getBuckets().get(kXRS_issuer_hash);
            String caIdentities = bucket.getContent();
            credentialManager.checkCaIdentities(caIdentities.split("[|]"));

            PEMCredential credential = credentialManager.getHostCredential();
            rsaSession.initializeForEncryption(credential.getKey());
            NestedBucketBuffer mainBucket =
                            ((NestedBucketBuffer) request.getBuckets().get(kXRS_main));
            XrootdBucket main = postProcessMainBucket(mainBucket.getNestedBuckets(),
                                                      Optional.empty(),
                                                      kXGS_cert);

            GSIBucketContainer responseBuckets =
                            new CertRequestBuckets(main,
                                                   CRYPTO_MODE,
                                                   dhParams(signDHParams),
                                                   dhParamBucketType,
                                                   SUPPORTED_CIPHER_ALGORITHM,
                                                   SUPPORTED_DIGESTS,
                                                   encodedHostCert(credential))
                                                .buildContainer();

            return new AuthenticationResponse(request,
                                              XrootdProtocol.kXR_authmore,
                                              responseBuckets.getSize(),
                                              PROTOCOL,
                                              kXGS_cert,
                                              responseBuckets.getBuckets());
        } catch (InvalidKeyException ikex) {
            LOGGER.error("Configured host-key could not be used for " +
                                         "signing: {}", ikex.getMessage());
            throw new XrootdException(kGSErrError,
                                      "Error when trying to sign client authentication tag.");
        } catch (CertificateEncodingException cee) {
            LOGGER.error("Could not extract contents of server certificate:" +
                                         " {}", cee.getMessage());
            throw new XrootdException(kGSErrError,
                                      "Error when trying to send server certificate.");
        } catch (IOException | GeneralSecurityException gssex) {
            LOGGER.error("Problems during signing of client authN tag " +
                                         "(algorithm {}): {}",
                         ASYNC_CIPHER_MODE,
                         gssex.getMessage() == null ?
                                         gssex.getClass().getName() : gssex.getMessage());
            throw new XrootdException(kGSErrError,
                                      "Error when trying to sign client authentication tag.");
        }
    }

    protected String validateCiphers(AuthenticationRequest request) throws XrootdException
    {
        StringBucket cipherBucket
                        = (StringBucket) request.getBuckets().get(kXRS_cipher_alg);

        return validateCiphers(cipherBucket.getContent().split("[:]"));
    }

    protected String validateDigests(AuthenticationRequest request) throws XrootdException
    {
        StringBucket digestBucket
                        = (StringBucket) request.getBuckets().get(kXRS_md_alg);

        return validateDigests(digestBucket.getContent().split("[:]"));
    }

    /**
     * @return the host certificate in encoded PEM form.
     */
    private String encodedHostCert(PEMCredential credential)
                    throws CertificateEncodingException
    {
        LOGGER.debug("Getting encoded host certificate from PEM credential.");
        X509Certificate certificate = credential.getCertificate();
        return CertUtil.certToPEM(certificate);
    }
}
