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

import java.net.InetSocketAddress;
import java.util.NoSuchElementException;
import java.util.concurrent.Executors;
import java.io.IOException;

import joptsimple.OptionSet;
import joptsimple.OptionException;

import org.jboss.netty.channel.ChannelPipelineFactory;
import org.jboss.netty.channel.ChannelFactory;
import org.jboss.netty.channel.group.ChannelGroup;
import org.jboss.netty.channel.group.DefaultChannelGroup;
import org.jboss.netty.channel.socket.nio.NioServerSocketChannelFactory;
import org.jboss.netty.bootstrap.ServerBootstrap;
import org.jboss.netty.logging.InternalLoggerFactory;
import org.jboss.netty.logging.Slf4JLoggerFactory;

public class DataServer
{
    /**
     * Switch Netty to slf4j for logging.
     */
    static
    {
        InternalLoggerFactory.setDefaultFactory(new Slf4JLoggerFactory());
    }

    private final DataServerConfiguration _configuration;

    public DataServer(DataServerConfiguration configuration)
    {
        _configuration = configuration;
    }

    public void start()
    {
        final ChannelGroup allChannels =
            new DefaultChannelGroup(DataServer.class.getName());
        ChannelPipelineFactory pipelineFactory =
            new DataServerPipelineFactory(_configuration, allChannels);
        ChannelFactory factory =
            new NioServerSocketChannelFactory(Executors.newCachedThreadPool(),
                                              Executors.newCachedThreadPool());
        final ServerBootstrap bootstrap = new ServerBootstrap(factory);
        bootstrap.setOption("child.tcpNoDelay", true);
        bootstrap.setOption("child.keepAlive", true);
        bootstrap.setPipelineFactory(pipelineFactory);
        allChannels.add(bootstrap.bind(new InetSocketAddress(_configuration.port)));

        Runtime.getRuntime().addShutdownHook(new Thread() {
                @Override
                public void run() {
                    allChannels.close().awaitUninterruptibly();
                    bootstrap.releaseExternalResources();
                }
            });
    }

    public static DataServerConfiguration loadConfiguration(String[] args)
        throws Exception
    {
        DataServerOptionParser parser = new DataServerOptionParser();
        OptionSet options = parser.parse(args);
        if (options.has(parser.help)) {
            parser.printHelpOn(System.out);
            System.exit(0);
        }
        return new DataServerConfiguration(parser, options);
    }

    public static void main(String[] args)
    {
        try {
            DataServer server = new DataServer(loadConfiguration(args));
            server.start();
        }  catch (OptionException e) {
            System.err.println(e.getMessage());
            System.err.println("Try --help for more information.");
            System.exit(2);
        }  catch (NoSuchElementException e) {
            System.err.println(e.getMessage());
            System.exit(1);
        }  catch (RuntimeException e) {
            e.printStackTrace();
            System.exit(1);
        }  catch (Exception e) {
            System.err.println(e.getMessage());
            System.exit(1);
        }
    }
}