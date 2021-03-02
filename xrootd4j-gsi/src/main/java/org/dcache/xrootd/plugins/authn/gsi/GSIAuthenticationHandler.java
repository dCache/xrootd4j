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

import eu.emi.security.authn.x509.impl.PEMCredential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;

import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.plugins.AuthenticationHandler;
import org.dcache.xrootd.plugins.authn.gsi.post49.GSIPost49ServerRequestHandler;
import org.dcache.xrootd.plugins.authn.gsi.pre49.GSIPre49ServerRequestHandler;
import org.dcache.xrootd.protocol.messages.AuthenticationRequest;
import org.dcache.xrootd.protocol.messages.OkResponse;
import org.dcache.xrootd.protocol.messages.XrootdResponse;
import org.dcache.xrootd.security.BufferDecrypter;
import org.dcache.xrootd.plugins.authn.gsi.GSIBucketUtils.BucketData;

import static org.dcache.xrootd.plugins.authn.gsi.GSIRequestHandler.CRYPTO_MODE;
import static org.dcache.xrootd.plugins.authn.gsi.GSIRequestHandler.PROTOCOL;
import static org.dcache.xrootd.plugins.authn.gsi.GSIRequestHandler.PROTO_WITH_DELEGATION;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_InvalidRequest;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.*;

/**
 * Handler for xrootd-security message exchange based on the GSI protocol.
 * Loosely based on the first reverse-engineering of xrootdsec-gsi, done by
 * Martin Radicke.
 */
public class GSIAuthenticationHandler implements AuthenticationHandler
{
    protected static final Logger               LOGGER
                    = LoggerFactory.getLogger(GSIAuthenticationHandler.class);

    /**
     * Container for principals and credentials found during the authentication
     * process.
     */
    private final Subject              subject;
    private final GSICredentialManager credentialManager;

    private GSIServerRequestHandler requestHandler;
    private boolean                 finished = false;

    public GSIAuthenticationHandler(GSICredentialManager credentialManager)
    {
        this.credentialManager = credentialManager;
        subject = new Subject();
    }

    /**
     * dispatcher function that initializes the diffie-hellman key agreement
     * session, checks the request for the correct protocol and calls the
     * actual handler functions.
     */
    @Override
    public XrootdResponse<AuthenticationRequest> authenticate(AuthenticationRequest request)
        throws XrootdException
    {
        BucketData data = GSIBucketUtils.deserializeData(request);

        /* check whether the protocol matches */
        if (!PROTOCOL.equalsIgnoreCase(data.getProtocol())) {
            requestHandler.cancelHandshake();
            throw new XrootdException(kXR_InvalidRequest,
                                      "Specified Protocol " + data.getProtocol() +
                                      " is not the protocol that was negotiated.");
        }

        if (requestHandler == null) {
            requestHandler = createRequestHandler(data.getVersion());
        }

        if (requestHandler.isRequestExpired()) {
            requestHandler.cancelHandshake();
            throw new XrootdException(kXR_InvalidRequest,
                                      "Client authentication request time expired.");
        }

        XrootdResponse<AuthenticationRequest> response;

        switch (data.getStep()) {
            case kXGC_none:
                response = new OkResponse<>(request);
                break;
            case kXGC_certreq:
                response = requestHandler.handleCertReqStep(request, data);
                LOGGER.debug("authenticate, processed certreq step "
                                             + "for stream {}, session {}.",
                             request.getStreamId(), request.getSession());
                break;
            case kXGC_cert:
                response = requestHandler.handleCertStep(request, data);
                finished = requestHandler.isFinished(data);
                LOGGER.debug("authenticate, processed cert step "
                                             + "for stream {}, session {}.",
                             request.getStreamId(), request.getSession());
                break;
            case kXGC_sigpxy:
                response = requestHandler.handleSigPxyStep(request, data);
                LOGGER.debug("authenticate, processed sigpxy step "
                                             + "for stream {}, session {}.",
                             request.getStreamId(), request.getSession());
                finished = requestHandler.isFinished(data);;
                break;
            default:
                requestHandler.cancelHandshake();
                throw new XrootdException(kGSErrBadOpt,
                                          "Error during authentication, " +
                                                          "unknown processing step: "
                                                          + data.getStep());
        }

        requestHandler.updateLastRequest();
        return response;
    }

    @Override
    public BufferDecrypter getDecrypter()
    {
        return requestHandler.getDecrypter();
    }

    /**
     * @return the supported protocol. The protocol string also
     * contains metainformation such as the host-certificate subject hash.
     */
    @Override
    public String getProtocol()
    {
        PEMCredential credential = credentialManager.getHostCredential();
        /* hashed principals are cached in CertUtil */
        String subjectHash =
            CertUtil.computeMD5Hash(credential.getCertificate()
                                              .getIssuerX500Principal());

        return "&P=" + PROTOCOL + "," +
                "v:" + GSIRequestHandler.PROTOCOL_VERSION + "," +
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

    private GSIServerRequestHandler createRequestHandler(Integer clientVersion)
                    throws XrootdException
    {
        if (clientVersion == null) {
            /*
             *  This method should be called only on the first exchange,
             *  so the client only needs to send it then (as it does).
             */
            throw new XrootdException(kGSErrBadProtocol, "Client did not "
                            + "provide GSI protocol version number.");
        }

        GSIServerRequestHandler handler;

        /*
         *  If the client supports a protocol of 4.9 or later,
         *  use the corresponding server implementation.
         *
         *  Else, use the previous.
         */
        if (clientVersion >= PROTO_WITH_DELEGATION) {
            handler = new GSIPost49ServerRequestHandler(subject, credentialManager);
        } else {
            handler = new GSIPre49ServerRequestHandler(subject, credentialManager);
        }

        LOGGER.info("Client protocol version was {}, using {}.",
                    clientVersion,
                    handler.getClass().getSimpleName());

        return handler;
    }
}
