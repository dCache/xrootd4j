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

import javax.security.auth.Subject;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.Optional;

import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.plugins.authn.gsi.GSICredentialManager;
import org.dcache.xrootd.plugins.authn.gsi.GSIServerRequestHandler;
import org.dcache.xrootd.protocol.messages.AuthenticationRequest;
import org.dcache.xrootd.protocol.messages.OkResponse;
import org.dcache.xrootd.protocol.messages.XrootdResponse;
import org.dcache.xrootd.security.NestedBucketBuffer;
import org.dcache.xrootd.security.XrootdBucket;
import org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType;

import static org.dcache.xrootd.protocol.XrootdProtocol.*;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType.kXRS_puk;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.kGSErrError;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.kGSErrSerialBuffer;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.kXGC_cert;

/**
 * Implementation of server side of GSI handshake prior to XrootD 4.9.
 * Does not support proxy delegation.
 */
public class GSIPre49ServerRequestHandler extends GSIServerRequestHandler
{
    public GSIPre49ServerRequestHandler(Subject subject,
                                        GSICredentialManager credentialManager)
                    throws XrootdException
    {
       super(subject, credentialManager);
    }

    @Override
    public int getProtocolVersion() {
        return PROTO_PRE_DELEGATION;
    }

    @Override
    public XrootdResponse<AuthenticationRequest>
        handleCertReqStep(AuthenticationRequest request) throws XrootdException
    {
        return handleCertReqStep(request, false, kXRS_puk);
    }

    /**
     * Handle the second step (reply by client to authmore).
     *
     * This involves finalizing the session key, verifying rsa certificate
     * and decrypting and verifying the signed hash.
     *
     * @param request AuthenticationRequest received by the client
     * @return OkResponse (verification is okay)
     */
    @Override
    public XrootdResponse<AuthenticationRequest>
        handleCertStep(AuthenticationRequest request) throws XrootdException
    {
        try {
            validateCiphers(request);
            validateDigests(request);

            Map<BucketType, XrootdBucket> receivedBuckets = request.getBuckets();

            finalizeSessionKey(receivedBuckets, kXRS_puk);

            NestedBucketBuffer mainBucket
                            = decryptMainBucketWithSessionKey(receivedBuckets,
                                                              "kXGC_cert");

            X509Certificate[] certChain =
                            processRSAVerification(mainBucket.getNestedBuckets(),
                                                   Optional.empty());

            subject.getPublicCredentials().add(certChain);

            rsaSession.initializeForDecryption(certChain[0].getPublicKey());

            verifySignedRTag(mainBucket.getNestedBuckets());

            return new OkResponse<>(request);
        } catch (InvalidKeyException ikex) {
            LOGGER.error("The key negotiated by DH key exchange appears to " +
                                         "be invalid: {}", ikex.getMessage());
            throw new XrootdException(kXR_DecryptErr,
                                      "Could not decrypt client" +
                                                      "information with negotiated key.");
         } catch (IOException ioex) {
            LOGGER.error("Could not deserialize main nested buffer {}",
                         ioex.getMessage() == null ?
                                         ioex.getClass().getName() : ioex.getMessage());
            throw new XrootdException(kGSErrSerialBuffer,
                                      "Could not decrypt encrypted " +
                                                      "client message.");
        } catch (GeneralSecurityException gssex) {
            LOGGER.error("Error during decrypting/server-side key exchange: {}",
                         gssex.getMessage());
            throw new XrootdException(kXR_DecryptErr,
                                      "Error in server-side cryptographic " +
                                                      "operations.");
        }
    }

    @Override
    public XrootdResponse<AuthenticationRequest> handleSigPxyStep
                    (AuthenticationRequest request) throws XrootdException
    {
        /*
         *  Should not happen.
         */
        throw new XrootdException(kGSErrError,
                                  "proxy request signing step not supported.");
    }

    @Override
    public boolean isFinished(AuthenticationRequest request)
    {
        return kXGC_cert == request.getStep();
    }

    @Override
    protected String getSyncCipherMode() {
        return SYNC_CIPHER_MODE_PADDED;
    }
}
