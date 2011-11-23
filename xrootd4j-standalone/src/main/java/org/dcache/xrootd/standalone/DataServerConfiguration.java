/**
 * Copyright (C) 2011 dCache.org <support@dcache.org>
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
 * License along with xrootd4j.  If not, see
 * <http://www.gnu.org/licenses/>.
 */
package org.dcache.xrootd.standalone;

import java.io.File;
import java.io.FilenameFilter;
import java.io.InputStream;
import java.io.IOException;
import java.util.NoSuchElementException;
import java.util.ServiceLoader;
import java.util.Properties;
import java.util.List;
import java.util.ArrayList;
import java.net.URL;
import java.net.MalformedURLException;
import java.net.URLClassLoader;

import joptsimple.OptionSet;

import org.dcache.xrootd.plugins.AuthenticationFactory;
import org.dcache.xrootd.plugins.AuthenticationProvider;
import org.dcache.xrootd.plugins.AuthorizationFactory;
import org.dcache.xrootd.plugins.AuthorizationProvider;

import com.google.common.io.PatternFilenameFilter;

public class DataServerConfiguration
{
    private final static FilenameFilter JAR_FILTER =
        new PatternFilenameFilter(".*\\.jar");
    private final static FilenameFilter PROPERTIES_FILTER =
        new PatternFilenameFilter(".*\\.properties");

    private final ClassLoader _pluginLoader;
    private final ServiceLoader<AuthenticationProvider> _authnProviders;
    private final ServiceLoader<AuthorizationProvider> _authzProviders;
    private final Properties _pluginDefaults;

    public final int port;
    public final File root;
    public final String authnPlugin;
    public final String authzPlugin;
    public final List<File> pluginPath;

    public final AuthenticationFactory authenticationFactory;
    public final AuthorizationFactory authorizationFactory;

    public DataServerConfiguration(DataServerOptionParser parser, OptionSet options)
        throws Exception
    {
        port = options.valueOf(parser.port);
        root = options.valueOf(parser.root);
        authnPlugin = options.valueOf(parser.authnPlugin);
        authzPlugin = options.valueOf(parser.authzPlugin);
        pluginPath = options.valuesOf(parser.pluginPath);

        _pluginDefaults = loadDefaultProperties(pluginPath);

        List<URL> jars = findPluginFiles(pluginPath, JAR_FILTER);
        _pluginLoader =
            new URLClassLoader(jars.toArray(new URL[0]));
        _authnProviders =
            ServiceLoader.load(AuthenticationProvider.class, _pluginLoader);
        _authzProviders =
            ServiceLoader.load(AuthorizationProvider.class, _pluginLoader);

        authenticationFactory = createAuthenticationFactory(authnPlugin);
        authorizationFactory = createAuthorizationFactory(authzPlugin);
    }

    private static Properties loadDefaultProperties(List<File> paths)
        throws IOException, MalformedURLException
    {
        Properties defaults = new Properties();
        for (URL url: findPluginFiles(paths, PROPERTIES_FILTER)) {
            InputStream in = url.openStream();
            try {
                defaults.load(in);
            } finally {
                in.close();
            }
        }
        return defaults;
    }

    private static List<URL> findPluginFiles(List<File> paths, FilenameFilter filter)
        throws MalformedURLException
    {
        ArrayList<URL> urls = new ArrayList<URL>();
        for (File dir: paths) {
            File[] plugins = dir.listFiles();
            if (plugins != null) {
                for (File plugin: plugins) {
                    File[] jars = plugin.listFiles(filter);
                    if (jars != null) {
                        for (File jar: jars) {
                            if (jar.isFile()) {
                                urls.add(jar.toURL());
                            }
                        }
                    }

                }
            }
        }
        return urls;
    }

    private Properties getPluginProperties()
    {
        Properties properties = new Properties(_pluginDefaults);
        properties.putAll(System.getProperties());
        return properties;
    }

    public final AuthenticationFactory createAuthenticationFactory(String plugin)
        throws Exception
    {
        Properties properties = getPluginProperties();
        for (AuthenticationProvider provider: _authnProviders) {
            AuthenticationFactory factory =
                provider.createFactory(plugin, properties);
            if (factory != null) {
                return factory;
            }
        }
        throw new NoSuchElementException("Authentication plugin not found: " + plugin);
    }

    public final AuthorizationFactory createAuthorizationFactory(String plugin)
        throws Exception
    {
        Properties properties = getPluginProperties();
        for (AuthorizationProvider provider: _authzProviders) {
            AuthorizationFactory factory =
                provider.createFactory(plugin, properties);
            if (factory != null) {
                return factory;
            }
        }
        throw new NoSuchElementException("Authorization plugin not found: " + plugin);
    }
}
