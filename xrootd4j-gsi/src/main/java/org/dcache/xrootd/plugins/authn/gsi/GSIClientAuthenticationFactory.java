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

import io.netty.channel.ChannelHandler;

import java.util.Properties;

import org.dcache.xrootd.plugins.ChannelHandlerFactory;

import static org.dcache.xrootd.plugins.authn.gsi.BaseGSIAuthenticationHandler.PROTOCOL;

/**
 * <p>Authentication factory that returns GSI security handlers to add to the
 *    third-party client channel pipeline.</p>
 *
 * <<p>In addition to loading host cert, key and crl validators, generates
 *     a proxy credential from the host cert and key, as required by
 *     the standard (SLAC) implementation of the server.</p>
 */
public class GSIClientAuthenticationFactory implements ChannelHandlerFactory {

    private final Properties properties;

    public GSIClientAuthenticationFactory(Properties properties)
    {
        this.properties = properties;
    }

    @Override
    public ChannelHandler createHandler()
    {
        GSICredentialManager credentialManager
                        = new GSICredentialManager(properties);

        /*
         *  This is an SPI interface method with no throws signature.
         *  Non-runtime exceptions on the credential load thus need to be logged.
         *
         *  If the credentials fail to load, the issue will soon be discovered
         *  when GSI TPC fails.
         */
        credentialManager.loadClientCredentials();

        GSIClientAuthenticationHandler handler =
                        new GSIClientAuthenticationHandler(credentialManager);
        return handler;
    }

    @Override
    public String getDescription()
    {
        return "GSI authentication client plugin for third-party transfers";
    }

    @Override
    public String getName()
    {
        return PROTOCOL;
    }
}
