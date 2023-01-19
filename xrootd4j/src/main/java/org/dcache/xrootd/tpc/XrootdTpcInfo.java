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
package org.dcache.xrootd.tpc;

import static com.google.common.base.Preconditions.checkState;
import static java.util.stream.Collectors.toSet;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_ArgMissing;
import static org.dcache.xrootd.tpc.XrootdTpcInfo.Cgi.AUTHZ;
import static org.dcache.xrootd.tpc.XrootdTpcInfo.Cgi.CHECKSUM;
import static org.dcache.xrootd.tpc.XrootdTpcInfo.Cgi.CLIENT;
import static org.dcache.xrootd.tpc.XrootdTpcInfo.Cgi.DLG;
import static org.dcache.xrootd.tpc.XrootdTpcInfo.Cgi.DLGON;
import static org.dcache.xrootd.tpc.XrootdTpcInfo.Cgi.DST;
import static org.dcache.xrootd.tpc.XrootdTpcInfo.Cgi.LOGICAL_NAME;
import static org.dcache.xrootd.tpc.XrootdTpcInfo.Cgi.RENDEZVOUS_KEY;
import static org.dcache.xrootd.tpc.XrootdTpcInfo.Cgi.SCGI;
import static org.dcache.xrootd.tpc.XrootdTpcInfo.Cgi.SIZE_IN_BYTES;
import static org.dcache.xrootd.tpc.XrootdTpcInfo.Cgi.SPR;
import static org.dcache.xrootd.tpc.XrootdTpcInfo.Cgi.SRC;
import static org.dcache.xrootd.tpc.XrootdTpcInfo.Cgi.TIME_TO_LIVE;

import com.google.common.base.Strings;
import java.io.Serializable;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.protocol.XrootdProtocol;
import org.dcache.xrootd.tpc.protocol.messages.InboundRedirectResponse;
import org.dcache.xrootd.util.FileStatus;
import org.dcache.xrootd.util.OpaqueStringParser;
import org.dcache.xrootd.util.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Metadata established via interaction between user client, source and
 *    destination in a third-party copy, occurring prior to the launching
 *    of an internal third-party copy operation.</p>
 *
 * Used to verify and coordinate the open and close requests.</p>
 */
public class XrootdTpcInfo {

    private static final Logger LOGGER = LoggerFactory.getLogger(XrootdTpcInfo.class);

    public enum Cgi {
        STAGE("tpc.stage"),
        RENDEZVOUS_KEY("tpc.key"),
        SRC("tpc.src"),
        DLG("tpc.dlg"),
        DLGON("tpc.dlgon"),
        DST("tpc.dst"),
        LOGICAL_NAME("tpc.lfn"),
        CLIENT("tpc.org"),
        CHECKSUM("tpc.cks"),
        TIME_TO_LIVE("tpc.ttl"),
        SIZE_IN_BYTES("oss.asize"),
        STR("tpc.str"),
        TPR("tpc.tpr"),
        /**
         *  This protocol should be used in conjunction with
         *  server-side settings to determine whether the
         *  TPC client should use TLS (= 'xroots').
         */
        SPR("tpc.spr"),
        /**
         *  This is the scgi added for delegation purposes.
         *  <p/>
         *  From the SLAC documentation:
         *  <p/>
         *  The CGI information from the source URL. This element needs to be
         *  specified only if a) delegation is being used and b) meaningful
         *  CGI is present on the source URL (see the notes on the definition
         *  of meaningful). Since a CGI string may not be the value of a
         *  CGI element, all ampersands in scgi should be converted to tab
         *  characters. The destination server is responsible for converting
         *  the tabs to ampersands before initiating the copy.
         */
        SCGI("tpc.scgi"),
        AUTHZ("authz");

        private static final Set<String> KEYS = EnumSet.allOf(Cgi.class)
              .stream()
              .map(Cgi::key)
              .collect(toSet());

        private String key;

        Cgi(String key) {
            this.key = key;
        }

        public String key() {
            return key;
        }

        static Set<String> keys() {
            return KEYS;
        }
    }

    public enum CksumType {
        ADLER32("adler32"),
        CRC32("crc32"),
        MD5("md5");

        private String key;

        CksumType(String key) {
            this.key = key;
        }

        public String key() {
            return key;
        }
    }

    public enum TpcStage {
        PLACEMENT("placement"),
        COPY("copy");

        private String key;

        TpcStage(String key) {
            this.key = key;
        }

        public String key() {
            return key;
        }
    }

    public enum Status {
        PENDING, READY, CANCELLED, ERROR
    }

    /**
     * The server has the following TPC role when processing this request.
     */
    public enum ServerRole {
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
    public enum ClientRole {
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
     *  Delegation
     */
    enum Delegation {
        OFF, ON;

        public static Delegation valueOf(Map<String, String> opaque) {
            String value = opaque.get(DLGON.key);
            if (value == null) {
                return OFF;
            }
            switch (opaque.get(DLGON.key)) {
                case "1":
                    return ON;
                default:
                    return OFF;
            }
        }
    }

    /**
     * Rendez-vous token provided by client.</p>
     */
    private final String key;

    /**
     * For eviction management.</p>
     */
    private final long createdTime;

    private Delegation dlgon;

    /**
     * User uid; used only for UNIX protocol.</p>
     */
    private Long uid;

    /**
     * User primary gid; used only for UNIX protocol.</p>
     */
    private Long gid;

    /**
     * The client identifier, in the form [user].[pid]@[hostname]</p>
     */
    private String org;

    /**
     * The host:port of the destination server.</p>
     */
    private String dst;

    /**
     * The host:port of the source server.</p>
     */
    private String src;

    /**
     * The hostname of the source server.</p>
     */
    private String srcHost;

    /**
     * The port of the source server.</p>
     */
    private Integer srcPort;

    /**
     * The logical file name.</p>
     */
    private String lfn;

    /**
     * Time to live (in seconds).</p>
     */
    private Long ttl;

    /**
     * Checksum type requested.</p>
     */
    private String cks;

    /**
     * Source size.</p>
     */
    private Long asize;

    /**
     * Status of the transfer request.</p>
     */
    private Status status;

    /**
     * dCache-assigned file descriptor.</p>
     */
    private int fd;

    /**
     * Set by the client to establish the point after which
     *    the destination server must request an open within the
     *    alotted time to live.</p>
     */
    private long startTime;

    /**
     * External (non xrootd-tpc) opaque key-values.</p>
     */
    private String external;

    /**
     * Possibly returned by a redirect.</p>
     */
    private String loginToken;

    /**
     * Source authorization token.</p>
     */
    private String sourceToken;

    /**
     * The stat info received on the TPC open call.</p>
     */
    private FileStatus fileStatus;

    /**
     * Delegated proxy object</p>
     */
    private Serializable delegatedProxy;

    private ServerRole serverRole;
    private ClientRole clientRole;

    /*
     *  Computed.
     */
    private OptionalLong fileSize = OptionalLong.empty();

    /**
     * The protocol to use when fetching the file, if specified by the client.
     */
    private Optional<String> sourceProtocol = Optional.empty();

    public XrootdTpcInfo(String key) {
        this.key = key;
        this.createdTime = System.currentTimeMillis();
        calculateRoles();
    }

    /**
     * Initializes everything from the map instance.
     *    Calling this constructor implies a READY status.</p>
     *    Ttl is not relevant.
     */
    public XrootdTpcInfo(Map<String, String> opaque) throws ParseException {
        this(opaque.get(RENDEZVOUS_KEY.key()));
        this.dlgon = Delegation.valueOf(opaque);
        this.lfn = opaque.get(LOGICAL_NAME.key());
        this.dst = opaque.get(DST.key());
        setSourceFromOpaque(opaque);
        this.cks = opaque.get(CHECKSUM.key());
        this.org = opaque.get(CLIENT.key());
        String asize = opaque.get(SIZE_IN_BYTES.key());
        if (asize != null) {
            this.asize = Long.parseLong(asize);
        }
        status = Status.READY;
        sourceProtocol = Optional.ofNullable(opaque.get(SPR.key()));
        findSourceToken(opaque);
        addExternal(opaque);
        calculateRoles();
    }

    public long computeFileSize() throws XrootdException {
        if (!fileSize.isPresent()) {
            if (fileStatus == null) {
                if (asize == null) {
                    throw new XrootdException(kXR_ArgMissing,
                          "Cannot read source; file size is unknown.");
                }
                fileSize = OptionalLong.of(asize); // asize not null here
            } else {
                fileSize = OptionalLong.of(fileStatus.getSize());
            }

            LOGGER.debug("computeFileSize: file status {}, oss.asize {}, "
                        + "computed size {}.",
                  fileStatus, asize, fileSize.getAsLong());
        }

        return fileSize.getAsLong();
    }

    public ServerRole getServerRole() {
        return serverRole;
    }

    public ClientRole getClientRole() {
        return clientRole;
    }

    public boolean isTpcRequest() {
        return clientRole != ClientRole.NON_TPC;
    }

    /**
     * Used in a two-phase sequence (client, server),
     *    to add information incrementally.</p>
     *
     * Will not overwrite existing non-null values.</p>
     */
    public synchronized XrootdTpcInfo addInfoFromOpaque(String slfn,
          Map<String, String> opaque)
          throws ParseException {
        if (lfn == null) {
            lfn = slfn;
        }

        this.dlgon = Delegation.valueOf(opaque);

        if (org == null) {
            org = opaque.get(CLIENT.key());
        }

        if (dst == null) {
            dst = opaque.get(DST.key());
        }

        if (src == null) {
            setSourceFromOpaque(opaque);
        }

        if (cks == null) {
            cks = opaque.get(CHECKSUM.key());
        }

        String value = opaque.get(TIME_TO_LIVE.key());

        if (value != null) {
            ttl = new Long(value);
            startTime = System.currentTimeMillis();
        }

        value = opaque.get(SIZE_IN_BYTES.key());
        if (value != null) {
            asize = Long.parseLong(value);
        }

        if (status == null) {
            status = Status.PENDING;
        } else if (status == Status.PENDING) {
            status = Status.READY;
        }

        if (!sourceProtocol.isPresent()) {
            sourceProtocol = Optional.ofNullable(opaque.get(SPR.key()));
        }

        if (sourceToken == null) {
            findSourceToken(opaque);
        }

        addExternal(opaque);
        calculateRoles();

        return this;
    }

    /**
     * Saves relevant fields which should remain the same,
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
        info.dlgon = dlgon;
        info.lfn = lfn;
        info.asize = asize;
        info.cks = cks;
        info.loginToken = response.getToken();
        info.delegatedProxy = delegatedProxy;
        info.uid = uid;
        info.gid = gid;

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

            Map<String, String> map = OpaqueStringParser.getOpaqueMap(opaque);

            /*
             *  The opaque data returned with the redirect will usually
             *  be the same as what the client provided the redirector,
             *  but it is possible that the redirector may substitute
             *  a new token to use against the new endpoint.
             *
             *  In either case, the token will be the value of 'authz'.
             */
            info.sourceToken = map.get(AUTHZ);

            info.addExternal(map);
        }

        /*
         *  NB: it is possible that a default token from ZTN at login exists.
         *  It would appear as the delegated proxy in this case.
         */

        info.status = Status.READY;
        info.calculateRoles();

        return info;
    }

    public boolean isTls() {
        return sourceProtocol.filter("xroots"::equals).isPresent();
    }

    public synchronized Status verify(String dst, String slfn, String org) {
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
    public String toString() {
        StringBuilder sb = new StringBuilder()
              .append("(dlgon ")
              .append(dlgon)
              .append("(key ")
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
              .append(")(source token ")
              .append(sourceToken)
              .append(")(external [")
              .append(external)
              .append("])")
              .toString();
    }

    public boolean isExpired() {
        return ttl != null && System.currentTimeMillis()
              > (startTime + TimeUnit.SECONDS.toMillis(ttl));
    }

    public String getCks() {
        return cks;
    }

    public long getCreatedTime() {
        return createdTime;
    }

    public Serializable getDelegatedProxy() {
        return delegatedProxy;
    }

    public String getSourceToken() {
        return sourceToken;
    }

    public String getExternal() {
        return external;
    }

    public int getFd() {
        return fd;
    }

    public Long getGid() {
        return gid;
    }

    public String getKey() {
        return key;
    }

    public String getLfn() {
        return lfn;
    }

    public String getLoginToken() {
        return loginToken;
    }

    public String getSrc() {
        return src;
    }

    public String getSrcHost() {
        return srcHost;
    }

    public Integer getSrcPort() {
        return srcPort;
    }

    public synchronized Status getStatus() {
        return status;
    }

    public Long getUid() {
        return uid;
    }

    public Delegation getDlgon() {
        return dlgon;
    }

    public void setUid(Long uid) {
        this.uid = uid;
    }

    public void setGid(Long gid) {
        this.gid = gid;
    }

    public void setDelegatedProxy(Serializable delegatedProxy) {
        this.delegatedProxy = delegatedProxy;
    }

    public void setFileStatus(FileStatus fileStatus) {
        this.fileStatus = fileStatus;
    }

    public void setFd(int fd) {
        this.fd = fd;
    }

    public synchronized void setStatus(Status status) {
        this.status = status;
    }

    private void addExternal(Map<String, String> opaque) {
        Map<String, String> external = new HashMap<>();
        for (Entry<String, String> entry : opaque.entrySet()) {
            if (!Cgi.keys().contains(entry.getKey())) {
                external.put(entry.getKey(), entry.getValue());
            }
        }
        this.external = OpaqueStringParser.buildOpaqueString(external);
    }

    private void setSourceFromOpaque(Map<String, String> map) {
        src = map.get(DLG.key());
        if (src == null) {
            src = map.get(SRC.key());
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
    public URI getSourceURL(String destinationPath) {
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

    private void calculateRoles() {
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
              (serverRole == ServerRole.TPC_SOURCE && clientRole != ClientRole.TPC_ORCHESTRATOR
                    && clientRole != ClientRole.TPC_DESTINATION)
              ||
              (serverRole == ServerRole.NON_TPC && clientRole != ClientRole.NON_TPC)
        ) {
            LOGGER.warn("Inconsistent xrootd-TPC roles ServerRole={} ClientRole={}",
                  serverRole, clientRole);
        }
    }

    private void findSourceToken(Map<String, String> opaque) throws ParseException {
        /*
         * The source token should be sought in the CGI element present when
         * doing third-party-copy using the delegation option.
         *
         * If the source opaque contains no authz element, we do not
         * substitute for it the token used on the path given to the destination.
         * However, if a login (ZTN) default exists, this will appear
         * as the delegated proxy and may be accessed as such during
         * authentication.
         */
        String scgi = opaque.get(SCGI.key());
        if (scgi != null) {
            scgi = scgi.replaceAll("\\t+",
                  String.valueOf(OpaqueStringParser.OPAQUE_PREFIX));
            Map<String, String> sourceOpaque
                  = OpaqueStringParser.getOpaqueMap(scgi);
            sourceToken = sourceOpaque.get(AUTHZ.key());
        }
    }
}
