/**
 * Copyright (C) 2011-2021 dCache.org <support@dcache.org>
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

import com.google.common.base.Strings;
import java.util.Properties;
import org.dcache.xrootd.plugins.ChannelHandlerFactory;
import org.dcache.xrootd.plugins.ChannelHandlerProvider;

public class TLSHandlerProvider implements ChannelHandlerProvider {

    public static final String PLUGIN = "ssl-handler";
    public static final String CLIENT_PLUGIN = "ssl-client-handler";

    private static final String FACTORY_FQN = "xrootd.security.tls.handler-factory.class";

    @Override
    public ChannelHandlerFactory createFactory(String plugin,
          Properties properties)
          throws Exception {
        Class<?> clzz = getFactoryClass(properties);
        SSLHandlerFactory factory = null;

        if (plugin.equals(PLUGIN)) {
            factory = (SSLHandlerFactory) clzz.newInstance();
            factory.initialize(properties, true);
        } else if (plugin.equals(CLIENT_PLUGIN)) {
            factory = (SSLHandlerFactory) clzz.newInstance();
            factory.initialize(properties, false);
        }

        return factory;
    }

    private Class<?> getFactoryClass(Properties properties)
          throws ClassNotFoundException, ClassCastException {
        String handlerImpl = properties.getProperty(FACTORY_FQN);

        if (Strings.emptyToNull(handlerImpl) == null) {
            throw new ClassNotFoundException("tls handler factory has not "
                  + "been defined.");
        }

        Class<?> clzz = Thread.currentThread().getContextClassLoader()
              .loadClass(handlerImpl);

        if (!SSLHandlerFactory.class.isAssignableFrom(clzz)) {
            String fatal = "The provided tls handler factory class must extend "
                  + SSLHandlerFactory.class;
            throw new ClassCastException(fatal);
        }

        return clzz;
    }
}
