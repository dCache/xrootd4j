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

import java.io.FileNotFoundException;
import java.util.Properties;

import org.dcache.xrootd.plugins.AuthenticationFactory;
import org.dcache.xrootd.plugins.AuthenticationHandler;
import org.dcache.xrootd.plugins.ProxyDelegationClient;

/**
 * Authentication factory that returns GSI security handlers.
 */
public class GSIAuthenticationFactory implements AuthenticationFactory
{
    private final Properties            properties;
    private final CertChainValidatorProvider validatorProvider;
    private final CredentialLoader credentialLoader;

    public GSIAuthenticationFactory(Properties properties)
                    throws FileNotFoundException
    {
        this.properties = properties;
        validatorProvider = new CertChainValidatorProvider(properties);
        credentialLoader = new CredentialLoader(properties,
                                                validatorProvider.getCertChainValidator());
    }

    @Override
    public AuthenticationHandler createHandler(ProxyDelegationClient proxyDelegationClient)
    {
        GSICredentialManager credentialManager
                        = new GSICredentialManager(properties,
                                                   credentialLoader,
                                                   validatorProvider.getCertChainValidator());
        credentialManager.setProxyDelegationClient(proxyDelegationClient);
        return new GSIAuthenticationHandler(credentialManager);
    }
}
