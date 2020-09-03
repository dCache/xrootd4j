/**
 * Copyright (C) 2011-2020 dCache.org <support@dcache.org>
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
package org.dcache.xrootd.tpc;

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.dcache.xrootd.protocol.XrootdProtocol;
import org.dcache.xrootd.tpc.protocol.messages.InboundRedirectResponse;
import org.dcache.xrootd.util.OpaqueStringParser;
import org.dcache.xrootd.util.ParseException;

import static com.google.common.base.Preconditions.checkState;

/**
 * <p>Metadata established via interaction between user client, source and
 *    destination in a third-party copy, occurring prior to the launching
 *    of an internal third-party copy operation.</p>
 *
 * <p>Used to verify and coordinate the open and close requests.</p>
 */
public class XrootdTpcInfo
{
    private static final Logger LOGGER = LoggerFactory.getLogger(XrootdTpcInfo.class);

    /**
     * <p>Opaque string name-value keys.</p>
     */
    public static final String STAGE = "tpc.stage";

    public static final String RENDEZVOUS_KEY = "tpc.key";

    public static final String SRC = "tpc.src";

    public static final String DLG = "tpc.dlg";

    public static final String DST = "tpc.dst";

    public static final String LOGICAL_NAME = "tpc.lfn";

    public static final String CLIENT = "tpc.org";

    public static final String CHECKSUM = "tpc.cks";

    public static final String TIME_TO_LIVE = "tpc.ttl";

    public static final String SIZE_IN_BYTES = "oss.asize";

    public static final String STR = "tpc.str";

    public static final String TPR = "tpc.tpr";

    /**
     *  This protocol should be used in conjunction with
     *  server-side settings to determine whether the
     *  TPC client should use TLS (= 'xroots').
     */
    public static final String SPR = "tpc.spr";

    /**
     * <p>Opaque string name-value constant values.</p>
     */
    public static final String PLACEMENT = "placement";

    public static final String COPY = "copy";

    public static final String ADLER32 = "adler32";

    public static final String CRC32 = "crc32";

    public static final String MD5 = "md5";

    private static final Set<String> TPC_KEYS
                    = ImmutableSet.of(STAGE,
                                      RENDEZVOUS_KEY,
                                      SRC,
                                      DST,
                                      LOGICAL_NAME,
                                      CLIENT,
                                      CHECKSUM,
                                      TIME_TO_LIVE,
                                      SIZE_IN_BYTES,
                                      STR,
                                      DLG,
                                      TPR,
                                      SPR);

    public enum Status
    {
        PENDING, READY, CANCELLED, ERROR
    }

    /**
     * The server has the following TPC role when processing this request.
     */
    public enum ServerRole
    {
        /** The request is not part of an Xrootd-TPC transfer. */
        NON_TPC,

        /**
         * The request is part of an Xrootd-TPC transfer and the server is
         * the source.
         */
        TPC_SOURCE,

        /**
         * The request is part of an Xrootd-TPC transfer and the server is
         * the destination.
         */
        TPC_DESTINATION
    }

    /**
     * The client has the following TPC role when making this request.
     */
    public enum ClientRole
    {
        /** The client is not making a TPC request. */
        NON_TPC,

        /**
         * This request is coming from a client that is orchestrating the
         * request.  The orchestrator contacts the source and destination
         * servers, and so coordinates the transfer.  This is typically the
         * command-line tool xrdcp.
         */
        TPC_ORCHESTRATOR,

        /**
         * The client is the TPC destination server.  This implies
         * {@literal ServerRole.TPC_SOURCE}.
         */
        TPC_DESTINATION
    }

    /**
     * <p>Rendez-vous token provided by client.</p>
     */
    private final String key;

    /**
     * <p>For eviction management.</p>
     */
    private final long createdTime;

    /**
     * <p>The client identifier, in the form [user].[pid]@[hostname]</p>
     */
    private String org;

    /**
     * <p>The host:port of the destination server.</p>
     */
    private String dst;

    /**
     * <p>The host:port of the source server.</p>
     */
    private String src;

    /**
     * <p>The hostname of the source server.</p>
     */
    private String srcHost;

    /**
     * <p>The port of the source server.</p>
     */
    private Integer srcPort;

    /**
     * <p>The logical file name.</p>
     */
    private String lfn;

    /**
     * <p>Time to live (in seconds).</p>
     */
    private Long ttl;

    /**
     * <p>Checksum type requested.</p>
     */
    private String cks;

    /**
     * <p>Source size.</p>
     */
    private long asize;

    /**
     * <p>Status of the transfer request.</p>
     */
    private Status status;

    /**
     * <p>dCache-assigned file descriptor.</p>
     */
    private int fd;

    /**
     * <p>Set by the client to establish the point after which
     *    the destination server must request an open within the
     *    alotted time to live.</p>
     */
    private long startTime;

    /**
     * <p>External (non xrootd-tpc) opaque key-values.</p>
     */
    private String external;

    /**
     * <p>Possibly returned by a redirect.</p>
     */
    private String loginToken;

    /**
     * <p>Delegated proxy object</p>
     */
    private Serializable delegatedProxy;

    private ServerRole serverRole;
    private ClientRole clientRole;

    /**
     * The protocol to use when fetching the file, if specified by the client.
     */
    private Optional<String> sourceProtocol = Optional.empty();

    public XrootdTpcInfo(String key)
    {
        this.key = key;
        this.createdTime = System.currentTimeMillis();
        calculateRoles();
    }

    /**
     * <p>Initializes everything from the map instance.
     *    Calling this constructor implies a READY status.</p>
     *    Ttl is not relevant.
     */
    public XrootdTpcInfo(Map<String, String> opaque)
    {
        this(opaque.get(RENDEZVOUS_KEY));
        this.lfn = opaque.get(LOGICAL_NAME);
        this.dst = opaque.get(DST);
        setSourceFromOpaque(opaque);
        this.cks = opaque.get(CHECKSUM);
        this.org = opaque.get(CLIENT);
        String asize = opaque.get(SIZE_IN_BYTES);
        if (asize != null) {
            this.asize = Long.parseLong(asize);
        }
        status = Status.READY;
        sourceProtocol = Optional.ofNullable(opaque.get(SPR));
        addExternal(opaque);
        calculateRoles();
    }

    public ServerRole getServerRole()
    {
        return serverRole;
    }

    public ClientRole getClientRole()
    {
        return clientRole;
    }

    public boolean isTpcRequest()
    {
        return clientRole != ClientRole.NON_TPC;
    }

    /**
     * <p>Used in a two-phase sequence (client, server),
     *    to add information incrementally.</p>
     *
     * <p>Will not overwrite existing non-null values.</p>
     */
    public synchronized XrootdTpcInfo addInfoFromOpaque(String slfn,
                                           Map<String, String> opaque)
    {
        if (this.lfn == null) {
            this.lfn = slfn;
        }

        if (this.org == null) {
            this.org = opaque.get(CLIENT);
        }

        if (this.dst == null) {
            this.dst = opaque.get(DST);
        }

        if (this.src == null) {
            setSourceFromOpaque(opaque);
        }

        if (this.cks == null) {
            this.cks = opaque.get(CHECKSUM);
        }

        String value = opaque.get("tpc.ttl");

        if (value != null) {
            this.ttl = new Long(value);
            this.startTime = System.currentTimeMillis();
        }

        value = opaque.get(SIZE_IN_BYTES);
        if (value != null) {
            this.asize = Long.parseLong(value);
        }

        if (this.status == null) {
            this.status = Status.PENDING;
        }

        if (!sourceProtocol.isPresent()) {
            sourceProtocol = Optional.ofNullable(opaque.get(SPR));
        }

        addExternal(opaque);
        calculateRoles();

        return this;
    }

    /**
     * <p>Saves relevant fields which should remain the same,
     *    and constructs new source endpoint info.</p>
     *
     * @param response received from source.
     * @return new info object which can be used to instantiate new client.
     */
    public XrootdTpcInfo copyForRedirect(InboundRedirectResponse response)
                    throws ParseException {
        XrootdTpcInfo info = new XrootdTpcInfo(key);

        URL url = response.getUrl();
        if (url != null) {
            info.srcHost = url.getHost();
            info.srcPort = url.getPort();
            info.sourceProtocol = Optional.ofNullable(url.getProtocol());
        } else {
            info.srcHost = response.getHost();
            info.srcPort = response.getPort();
            info.sourceProtocol = sourceProtocol;
        }

        info.src = info.srcHost + ":" + info.srcPort;

        info.lfn = lfn;
        info.asize = asize;
        info.cks = cks;
        info.loginToken = response.getToken();
        info.delegatedProxy = delegatedProxy;

        String opaque = response.getOpaque();

        if (opaque == null && url != null) {
            opaque = url.getQuery();
        }

        if (opaque != null) {
            /*
             * Perform the transformation to map and back as a way of
             * checking that the string parses.
             */
            if (!opaque.startsWith("?")) {
                opaque = "?" + opaque;
            }
            info.addExternal(OpaqueStringParser.getOpaqueMap(opaque));
        }

        info.status = Status.READY;
        info.calculateRoles();

        return info;
    }

    public boolean isTls()
    {
        return sourceProtocol.filter("xroots"::equals).isPresent();
    }

    public synchronized Status verify(String dst, String slfn, String org)
    {
        if (this.status == Status.ERROR) {
            return this.status;
        }

        if (this.dst == null) {
            /*
             *  Client open has not yet occurred.
             */
            return Status.PENDING;
        }

        if (dst.equals(this.dst)
                        && slfn.equals(this.lfn)
                        && org.equals(this.org)
                        && !isExpired()) {
            this.status = Status.READY;
        } else {
            /*
             *  rendezvous info does not match or ttl has expired.
             */
            this.status = Status.CANCELLED;
        }

        return this.status;
    }

    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder().append("(key ")
                                  .append(key)
                                  .append(")(dst ")
                                  .append(dst)
                                  .append(")(src ")
                                  .append(srcHost)
                                  .append(":")
                                  .append(srcPort)
                                  .append(")(org ")
                                  .append(org)
                                  .append(")(lfn ")
                                  .append(lfn)
                                  .append(")(ttl ")
                                  .append(ttl)
                                  .append(")(cks ")
                                  .append(cks)
                                  .append(")(asize ")
                                  .append(asize)
                                  .append(")(fhandle ")
                                  .append(fd)
                                  .append(')');

        sourceProtocol.ifPresent(p -> sb.append("(spr ").append(p).append(')'));

        return sb.append("(status ")
                .append(status)
                .append(")(token ")
                .append(loginToken)
                .append(")(external [")
                .append(external)
                .append("])")
                .toString();
    }

    public boolean isExpired()
    {
        return ttl != null && System.currentTimeMillis()
                        > (startTime + TimeUnit.SECONDS.toMillis(ttl));
    }

    public long getAsize()
    {
        return asize;
    }

    public String getCks()
    {
        return cks;
    }

    public long getCreatedTime()
    {
        return createdTime;
    }

    public Serializable getDelegatedProxy()
    {
        return delegatedProxy;
    }

    public String getExternal()
    {
        return external;
    }

    public String getDst()
    {
        return dst;
    }

    public int getFd()
    {
        return fd;
    }

    public String getKey()
    {
        return key;
    }

    public String getLfn()
    {
        return lfn;
    }

    public String getLoginToken()
    {
        return loginToken;
    }

    public String getOrg()
    {
        return org;
    }

    public String getSrc()
    {
        return src;
    }

    public String getSrcHost()
    {
        return srcHost;
    }

    public Integer getSrcPort()
    {
        return srcPort;
    }

    public synchronized Status getStatus()
    {
        return status;
    }

    public Long getTtl()
    {

        return ttl;
    }

    public void setAsize(long asize)
    {
        this.asize = asize;
    }

    public void setCks(String cks)
    {
        this.cks = cks;
    }

    public void setDelegatedProxy(Serializable delegatedProxy)
    {
        this.delegatedProxy = delegatedProxy;
    }

    public void setDst(String dst)
    {
        this.dst = dst;
        calculateRoles();
    }

    public void setFd(int fd)
    {
        this.fd = fd;
    }

    public void setLfn(String lfn)
    {
        this.lfn = lfn;
    }

    public void setLoginToken(String loginToken)
    {
        this.loginToken = loginToken;
    }

    public void setOrg(String org)
    {
        this.org = org;
        calculateRoles();
    }

    public void setSrc(String src)
    {
        this.src = src;
        calculateRoles();
    }

    public void setSrcHost(String srcHost)
    {
        this.srcHost = srcHost;
    }

    public void setSrcPort(Integer srcPort)
    {
        this.srcPort = srcPort;
    }

    public synchronized void setStatus(Status status)
    {
        this.status = status;
    }

    public void setTtl(Long ttl)
    {
        this.ttl = ttl;
    }

    private void addExternal(Map<String,String> opaque)
    {
        Map<String, String> external = new HashMap<>();
        for (Entry<String, String> entry: opaque.entrySet()) {
            if (!TPC_KEYS.contains(entry.getKey())) {
                external.put(entry.getKey(), entry.getValue());
            }
        }
        this.external = OpaqueStringParser.buildOpaqueString(external);
    }

    private void setSourceFromOpaque(Map<String, String> map)
    {
        src = map.get(DLG);
        if (src == null) {
            src = map.get(SRC);
        }
        if (src != null) {
            /*
             *  there may be a uname prefix, so remove it
             */
            int at = src.indexOf("@");
            if (at >= 0) {
                src = src.substring(at + 1);
            }
            String[] source = src.split(":");
            srcHost = source[0];
            if (source.length > 1 && Strings.emptyToNull(source[1]) != null) {
                srcPort = Integer.parseInt(source[1]);
            } else {
                srcPort = XrootdProtocol.DEFAULT_PORT;
            }
        }
    }

    /**
     * The source URL if the TPC request targets the destination server.
     * @param destinationPath The path of the file on the destination server.
     * @return The URL of the source.
     * @throws IllegalStateException if tpc.src is not defined.
     */
    public URI getSourceURL(String destinationPath)
    {
        checkState(src != null, "'tpc.src' element is missing");

        int port = (srcPort == null || srcPort == XrootdProtocol.DEFAULT_PORT)
                ? -1
                : srcPort;

        String sourcePath = lfn == null ? destinationPath : lfn;
        String scheme = sourceProtocol.orElse("xroot");

        try {
            return new URI(scheme, null, srcHost, port,
                    sourcePath.startsWith("/") ? sourcePath : ("/" + sourcePath),
                    null, null);
        } catch (URISyntaxException e) {
            throw new RuntimeException(e.toString(), e);
        }
    }

    private void calculateRoles()
    {
        if (org != null) {
            clientRole = ClientRole.TPC_DESTINATION;
        } else if (src != null || dst != null) {
            clientRole = ClientRole.TPC_ORCHESTRATOR;
        } else {
            clientRole = ClientRole.NON_TPC;
        }

        if (src != null) {
            serverRole = ServerRole.TPC_DESTINATION;
        } else if (dst != null || org != null) {
            serverRole = ServerRole.TPC_SOURCE;
        } else {
            serverRole = ServerRole.NON_TPC;
        }

        if ((serverRole == ServerRole.TPC_DESTINATION && clientRole != ClientRole.TPC_ORCHESTRATOR)
               ||
            (serverRole == ServerRole.TPC_SOURCE && clientRole != ClientRole.TPC_ORCHESTRATOR && clientRole != ClientRole.TPC_DESTINATION)
               ||
            (serverRole == ServerRole.NON_TPC && clientRole != ClientRole.NON_TPC)
           ) {
            LOGGER.warn("Inconsistent xrootd-TPC roles ServerRole={} ClientRole={}",
                    serverRole, clientRole);
        }
    }
}
