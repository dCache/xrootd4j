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
package org.dcache.xrootd.standalone;

import com.google.common.io.PatternFilenameFilter;
import joptsimple.OptionSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Properties;
import java.util.ServiceLoader;

import org.dcache.xrootd.core.XrootdAuthenticationHandlerProvider;
import org.dcache.xrootd.core.XrootdAuthorizationHandlerProvider;
import org.dcache.xrootd.plugins.ChannelHandlerFactory;
import org.dcache.xrootd.plugins.ChannelHandlerProvider;

public class DataServerConfiguration
{
    private static final Logger _log =
        LoggerFactory.getLogger(DataServerConfiguration.class);

    private static final FilenameFilter JAR_FILTER =
        new PatternFilenameFilter(".*\\.jar");
    private static final FilenameFilter PROPERTIES_FILTER =
        new PatternFilenameFilter(".*\\.properties");

    private final ClassLoader _pluginLoader;
    private final ServiceLoader<ChannelHandlerProvider> _channelHandlerProviders;
    private final Properties _pluginDefaults;

    public final int port;
    public final File root;
    public final List<File> pluginPath;
    public final List<String> channelHandlerPlugins;
    public final boolean useBlockingIo;
    public final boolean useZeroCopy;

    public final List<ChannelHandlerFactory> channelHandlerFactories;

    public DataServerConfiguration(DataServerOptionParser parser, OptionSet options)
        throws Exception
    {
        port = options.valueOf(parser.port);
        root = options.valueOf(parser.root);
        pluginPath = options.valuesOf(parser.pluginPath);
        channelHandlerPlugins = options.valuesOf(parser.handlerPlugins);
        useBlockingIo = options.has(parser.blocking);
        useZeroCopy = options.has(parser.zeroCopy);

        _pluginDefaults = loadDefaultProperties(pluginPath);

        List<URL> jars = findPluginFiles(pluginPath, JAR_FILTER);

        _log.info("Searching the following additional jars for plugins: {}", jars);

        _pluginLoader =
            new URLClassLoader(jars.toArray(new URL[jars.size()]));
        XrootdAuthenticationHandlerProvider.setPluginClassLoader(_pluginLoader);
        XrootdAuthorizationHandlerProvider.setPluginClassLoader(_pluginLoader);
        _channelHandlerProviders =
            ServiceLoader.load(ChannelHandlerProvider.class, _pluginLoader);

        channelHandlerFactories = new ArrayList<>();
        for (String plugin: channelHandlerPlugins) {
            channelHandlerFactories.add(createHandlerFactory(plugin));
        }
    }

    private static Properties loadDefaultProperties(List<File> paths)
        throws IOException, MalformedURLException
    {
        Properties defaults = new Properties();
        for (URL url: findPluginFiles(paths, PROPERTIES_FILTER)) {
            try (InputStream in = url.openStream()) {
                defaults.load(in);
            }
        }
        return defaults;
    }

    private static List<URL> findPluginFiles(List<File> paths, FilenameFilter filter)
        throws MalformedURLException
    {
        ArrayList<URL> urls = new ArrayList<>();
        for (File dir: paths) {
            File[] plugins = dir.listFiles();
            if (plugins != null) {
                for (File plugin: plugins) {
                    _log.debug("Scanning plugin directory {}", plugin);
                    File[] files = plugin.listFiles(filter);
                    if (files != null) {
                        for (File file: files) {
                            if (file.isFile()) {
                                urls.add(file.toURI().toURL());
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

    public final ChannelHandlerFactory createHandlerFactory(String plugin)
            throws Exception
    {
        Properties properties = getPluginProperties();
        for (ChannelHandlerProvider provider: _channelHandlerProviders) {
            ChannelHandlerFactory factory =
                    provider.createFactory(plugin, properties);
            if (factory != null) {
                _log.debug("ChannelHandler plugin {} is provided by {}", plugin, provider.getClass());
                return factory;
            } else {
                _log.debug("ChannelHandler plugin {} could not be provided by {}", plugin, provider.getClass());
            }
        }
        throw new NoSuchElementException("Channel handler plugin not found: " + plugin);
    }
}
