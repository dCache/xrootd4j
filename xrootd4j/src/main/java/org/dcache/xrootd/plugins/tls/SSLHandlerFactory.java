/**
 * Copyright (C) 2011-2023 dCache.org <support@dcache.org>
 * 
 * This file is part of xrootd4j.
 * 
 * xrootd4j is free software: you can redistribute it and/or modify it under the terms of the GNU
 * Lesser General Public License as published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 * 
 * xrootd4j is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License along with xrootd4j.  If
 * not, see http://www.gnu.org/licenses/.
 */
package org.dcache.xrootd.plugins.tls;

import io.netty.buffer.ByteBufAllocator;
import io.netty.channel.ChannelHandler;
import io.netty.handler.ssl.SslContext;
import java.util.List;
import java.util.Properties;
import org.dcache.xrootd.plugins.ChannelHandlerFactory;

/**
 *  Provides an SSLHandler constructed from the SSLContext established
 *  via properties.  Each handler has a separate SSLEngine.  The handler
 *  is always constructed in startTls mode, as it should not be added
 *  to the pipeline until ready to send the last unprotected response
 *  (server) or initiate the TLS handshake (client).
 *  <p/>
 *  Construction of the SSL Context is implementation specific, so
 *  a subclass of this class must be provided.
 */
public abstract class SSLHandlerFactory implements ChannelHandlerFactory {

    public static final String SERVER_TLS = "tls";
    public static final String CLIENT_TLS = "tls-client";

    public static SSLHandlerFactory getHandlerFactory(String name,
          List<ChannelHandlerFactory> list) {
        return (SSLHandlerFactory) list.stream()
              .filter(h -> name.equalsIgnoreCase(h.getName()))
              .findFirst().orElse(null);
    }

    protected SslContext sslContext;
    protected boolean startTls;
    protected String name;

    public void initialize(Properties properties, boolean startTls) throws Exception {
        this.startTls = startTls;
        name = startTls ? SERVER_TLS : CLIENT_TLS;
        sslContext = buildContext(properties);
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public String getDescription() {
        return "Creates and configures Netty SslHandler for the xrootd pipeline.";
    }

    @Override
    public ChannelHandler createHandler() {
        return sslContext.newHandler(ByteBufAllocator.DEFAULT);
    }

    /**
     * Called by the provider during initialization.
     */
    protected abstract SslContext buildContext(Properties properties) throws Exception;
}
