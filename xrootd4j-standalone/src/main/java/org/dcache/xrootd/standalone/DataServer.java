/**
 * Copyright (C) 2011-2013 dCache.org <support@dcache.org>
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

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.ChannelOption;
import io.netty.channel.group.ChannelGroup;
import io.netty.channel.group.DefaultChannelGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.oio.OioEventLoopGroup;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.channel.socket.oio.OioServerSocketChannel;
import io.netty.util.internal.logging.InternalLoggerFactory;
import io.netty.util.internal.logging.Slf4JLoggerFactory;
import joptsimple.OptionException;
import joptsimple.OptionSet;

import java.util.NoSuchElementException;

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
        final ServerBootstrap bootstrap = new ServerBootstrap();
        bootstrap
                .group(_configuration.useBlockingIo ? new OioEventLoopGroup() : new NioEventLoopGroup())
                .channel(_configuration.useBlockingIo ? OioServerSocketChannel.class : NioServerSocketChannel.class)
                .option(ChannelOption.TCP_NODELAY, true)
                .option(ChannelOption.SO_KEEPALIVE, true)
                .childHandler(new DataServerChannelInitializer(_configuration))
                .localAddress(_configuration.port)
                .bind();

        Runtime.getRuntime().addShutdownHook(new Thread() {
                @Override
                public void run() {
                    bootstrap.shutdown();
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
