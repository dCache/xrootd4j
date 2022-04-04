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
package org.dcache.xrootd.standalone;

import java.io.File;
import static java.util.Arrays.asList;

import joptsimple.OptionParser;
import joptsimple.OptionSpec;

public class DataServerOptionParser extends OptionParser
{
    public final OptionSpec<Integer> port;
    public final OptionSpec<Void> help;
    public final OptionSpec<File> root;
    public final OptionSpec<String> handlerPlugins;
    public final OptionSpec<File> pluginPath;
    public final OptionSpec<Void> blocking;
    public final OptionSpec<Void> zeroCopy;

    {
        port = acceptsAll(asList("p", "port"))
            .withRequiredArg()
            .describedAs("TCP port")
            .ofType(Integer.class)
            .defaultsTo(1094);
        help = acceptsAll(asList("h", "?", "help"), "show help");
        root = acceptsAll(asList("r", "root"), "root directory")
            .withRequiredArg()
            .describedAs("path")
            .ofType(File.class)
            .defaultsTo(new File("/tmp"));
        handlerPlugins = acceptsAll(asList("handler"), "channel handler plugins")
            .withRequiredArg()
            .describedAs("plugin")
            .ofType(String.class)
            .withValuesSeparatedBy(',')
            .defaultsTo("authn:none");
        pluginPath = acceptsAll(asList("plugins"), "search path for plugins")
            .withRequiredArg()
            .withValuesSeparatedBy(File.pathSeparatorChar)
            .describedAs("url")
            .ofType(File.class);
        blocking = acceptsAll(asList("b", "blocking"), "Use blocking IO calls");
        zeroCopy = acceptsAll(asList("z", "zerocopy"), "Use zero copy reads");
    }
}
