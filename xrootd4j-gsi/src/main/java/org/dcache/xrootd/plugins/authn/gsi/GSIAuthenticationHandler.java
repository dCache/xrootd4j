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
package org.dcache.xrootd.plugins.authn.gsi;

import eu.emi.security.authn.x509.impl.PEMCredential;

import javax.security.auth.Subject;

import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.plugins.AuthenticationHandler;
import org.dcache.xrootd.plugins.authn.gsi.pre49.GSIPre49ServerRequestHandler;
import org.dcache.xrootd.protocol.messages.AuthenticationRequest;
import org.dcache.xrootd.protocol.messages.OkResponse;
import org.dcache.xrootd.protocol.messages.XrootdResponse;
import org.dcache.xrootd.security.BufferDecrypter;

import static org.dcache.xrootd.plugins.authn.gsi.GSIRequestHandler.CRYPTO_MODE;
import static org.dcache.xrootd.plugins.authn.gsi.GSIRequestHandler.PROTOCOL;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_InvalidRequest;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.kXGC_cert;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.kXGC_certreq;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.kXGC_none;

/**
 * Handler for xrootd-security message exchange based on the GSI protocol.
 * Loosely based on the first reverse-engineering of xrootdsec-gsi, done by
 * Martin Radicke.
 */
public class GSIAuthenticationHandler implements AuthenticationHandler
{
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
        /* check whether the protocol matches */
        if (!PROTOCOL.equalsIgnoreCase(request.getProtocol())) {
            throw new XrootdException(kXR_InvalidRequest,
                                      "Specified Protocol " + request.getProtocol() +
                                      " is not the protocol that was negotiated.");
        }

        if (requestHandler == null) {
            /*
             *  REVISIT  check version and create the correct handler
             *           when 49+ protocol added
             */
            requestHandler = new GSIPre49ServerRequestHandler(subject, credentialManager);
        }

        if (requestHandler.isRequestExpired()) {
            // TODO throw the proper XrootdException
        }

        XrootdResponse<AuthenticationRequest> response;

        switch (request.getStep()) {
            case kXGC_none:
                response = new OkResponse<>(request);
                break;
            case kXGC_certreq:
                response = requestHandler.handleCertReqStep(request);
                break;
            case kXGC_cert:
                response = requestHandler.handleCertStep(request);
                finished = true;
                break;
            default:
                throw new XrootdException(kXR_InvalidRequest,
                                          "Error during authentication, " +
                                                          "unknown processing step: "
                                                          + request.getStep());
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
            CertUtil.computeMD5Hash(credentialManager.getHostCredential()
                                                     .getCertificate()
                                                     .getIssuerX500Principal());

        int version = requestHandler == null ?
                        GSIRequestHandler.PROTOCOL_VERSION :
                        requestHandler.getProtocolVersion();

        return "&P=" + PROTOCOL + "," +
                "v:" + version + "," +
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
