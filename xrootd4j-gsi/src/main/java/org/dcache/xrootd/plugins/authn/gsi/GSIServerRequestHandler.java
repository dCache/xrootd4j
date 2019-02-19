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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;

import java.security.GeneralSecurityException;

import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.protocol.messages.AuthenticationRequest;
import org.dcache.xrootd.protocol.messages.XrootdResponse;
import org.dcache.xrootd.security.BufferDecrypter;

import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_ServerError;

public abstract class GSIServerRequestHandler extends GSIRequestHandler
{
    protected static Logger LOGGER
                = LoggerFactory.getLogger(GSIServerRequestHandler.class);

    protected Subject              subject;

    protected GSIServerRequestHandler(Subject subject,
                                      GSICredentialManager credentialManager)
                    throws XrootdException
    {
        super(credentialManager);
        this.subject = subject;
        try {
            dhSession = new DHSession(true);
        } catch (GeneralSecurityException gssex) {
            LOGGER.error("Error setting up cryptographic classes: {}",
                         gssex.getMessage());
            throw new XrootdException(kXR_ServerError,
                                      "Server probably misconfigured.");
        }
    }

    public BufferDecrypter getDecrypter()
    {
        return bufferHandler;
    }

    public abstract XrootdResponse<AuthenticationRequest>
        handleCertReqStep(AuthenticationRequest request)
                    throws XrootdException;

    public abstract XrootdResponse<AuthenticationRequest>
        handleCertStep(AuthenticationRequest request)
                    throws XrootdException;
}
