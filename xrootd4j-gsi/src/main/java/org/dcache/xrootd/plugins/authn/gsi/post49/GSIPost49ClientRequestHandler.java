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
package org.dcache.xrootd.plugins.authn.gsi.post49;

import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.impl.KeyAndCertCredential;
import io.netty.channel.ChannelHandlerContext;

import java.io.Serializable;
import java.security.KeyStoreException;
import java.util.Map;
import java.util.Optional;

import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.plugins.authn.gsi.CertUtil;
import org.dcache.xrootd.plugins.authn.gsi.GSIBucketContainer;
import org.dcache.xrootd.plugins.authn.gsi.GSIBucketContainerBuilder;
import org.dcache.xrootd.plugins.authn.gsi.GSIClientRequestHandler;
import org.dcache.xrootd.plugins.authn.gsi.GSICredentialManager;
import org.dcache.xrootd.plugins.authn.gsi.SerializableX509Credential;
import org.dcache.xrootd.plugins.authn.gsi.GSIBucket;
import org.dcache.xrootd.plugins.authn.gsi.GSIBucketUtils.BucketData;
import org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType;
import org.dcache.xrootd.tpc.XrootdTpcClient;
import org.dcache.xrootd.tpc.protocol.messages.InboundAuthenticationResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundErrorResponse;
import org.dcache.xrootd.tpc.protocol.messages.OutboundAuthenticationRequest;

import static org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType.kXRS_cipher;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.kGSErrError;

public class GSIPost49ClientRequestHandler extends GSIClientRequestHandler
{
    protected class PxyreqResponseBuckets extends GSIBucketContainerBuilder
    {
        private GSIBucket mainBucket;

        public PxyreqResponseBuckets(GSIBucket mainBucket) throws XrootdException {
            this.mainBucket = mainBucket;
        }

        @Override
        public GSIBucketContainer buildContainer() {
            return GSIBucketContainerBuilder.build(mainBucket);
        }
    }

    private X509Credential delegatedProxy;

    public GSIPost49ClientRequestHandler(GSICredentialManager credentialManager,
                                         XrootdTpcClient client)
    {
        super(credentialManager, client);
    }

    @Override
    public int getProtocolVersion()
    {
        return PROTO_WITH_DELEGATION;
    }

    @Override
    protected void handleAuthenticationError(InboundErrorResponse response)
                    throws XrootdException {
        String message = response.getErrorMessage() + " –– user proxy was "
                            + client.getInfo().getDelegatedProxy() == null
                            ? "not " : "" + "delegated.";
        throw new XrootdException(response.getError(), message);
    }

    public OutboundAuthenticationRequest handleCertStep(InboundAuthenticationResponse response,
                                                        BucketData data,
                                                        ChannelHandlerContext ctx)
                    throws XrootdException
    {
        return handleCertStep(response,
                              data,
                              ctx,
                              kXRS_cipher,
                              true,
                              Optional.of(getClientPublicKeyPem()),
                              Optional.of(client.getUname()));
    }

    @Override
    protected X509Credential getClientCredential()
    {
        return delegatedProxy;
    }

    @Override
    protected Optional<Integer> getClientOpts()
    {
        /*
         *  Explicitly state to the server that this client
         *  does not sign proxy requests (it does not need to).
         *
         *  (kOptsSigReq = 0x04 is supported, i.e., third bit is set).
         */
        return Optional.of(0);
    }

    @Override
    protected String getSyncCipherMode() {
        return SYNC_CIPHER_MODE_UNPADDED;
    }

    @Override
    protected void loadClientCredential() throws XrootdException
    {
        LOGGER.debug("Loading client credential.");

        Serializable serializable = client.getInfo().getDelegatedProxy();

        if (serializable != null) {
            try {
                SerializableX509Credential proxy
                                = (SerializableX509Credential) serializable;
                delegatedProxy = new KeyAndCertCredential(proxy.getPrivateKey(),
                                                          proxy.getCertChain());
                credentialManager.setIssuerHashesFromCredential(delegatedProxy);
            } catch (ClassCastException e) {
                throw new XrootdException(kGSErrError, "delegated proxy was "
                                + "of wrong type: " + serializable.getClass());
            } catch (KeyStoreException e) {
                throw new XrootdException(kGSErrError,
                                          "problem with delegated proxy: " +
                                                          e.getMessage());
            }
        }

        /*
         * if proxy is null, fail downstream.
         */
    }

    @Override
    protected boolean usePadded()
    {
        return !noPadding;
    }

    protected String validateCiphers(Map<BucketType, GSIBucket> bucketMap)
                    throws XrootdException
    {
        return super.validateCiphers(bucketMap)
                        + SESSION_IV_DELIM + SESSION_IV_LEN;
    }

    private String getClientPublicKeyPem()
    {
        return CertUtil.toPEM(delegatedProxy.getCertificate()
                                            .getPublicKey()
                                            .getEncoded(),
                              PUBLIC_KEY_HEADER,
                              PUBLIC_KEY_FOOTER);
    }
}
