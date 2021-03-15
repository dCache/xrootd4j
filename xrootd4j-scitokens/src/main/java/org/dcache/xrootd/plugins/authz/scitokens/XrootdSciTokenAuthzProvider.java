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
package org.dcache.xrootd.plugins.authz.scitokens;

import com.google.common.base.Strings;

import java.util.Properties;

import org.dcache.xrootd.plugins.AuthorizationFactory;
import org.dcache.xrootd.plugins.AuthorizationProvider;

/**
 * Provides the specific implementation of the factory based on
 * discovery of the class from the properties.
 */
public class XrootdSciTokenAuthzProvider implements AuthorizationProvider
{
    static final String NAME = "scitokens";

    private static final String FACTORY_FQN = "xrootd.plugin!scitokens.authz-factory.class";
    private static final String STRICT_PROPERTY = "xrootd.plugin!scitokens.strict";

    @Override
    public AuthorizationFactory createFactory(String plugin, Properties properties)
                    throws Exception
    {
        if (NAME.equals(plugin)) {
            Class<?> clzz = getFactoryClass(properties);
            String strict = properties.getProperty(STRICT_PROPERTY,
                                                   "false");
            AbstractSciTokenAuthzFactory factory
                            = (AbstractSciTokenAuthzFactory) clzz.newInstance();
            factory.setStrict(Boolean.valueOf(strict));
            return factory;
        }

        return null;
    }

    private Class<?> getFactoryClass(Properties properties)
                    throws ClassNotFoundException
    {
        String handlerImpl = properties.getProperty(FACTORY_FQN);

        if (Strings.emptyToNull(handlerImpl) == null) {
            throw new ClassNotFoundException("scitoken factory has not been "
                                                             + "defined.");
        }

        Class<?> clzz = Thread.currentThread().getContextClassLoader()
                              .loadClass(handlerImpl);

        if (!AbstractSciTokenAuthzFactory.class.isAssignableFrom(clzz)) {
            String fatal = "The provided token verifier class must implement "
                            + AbstractSciTokenAuthzFactory.class;
            throw new ClassCastException(fatal);
        }

        return clzz;
    }
}
