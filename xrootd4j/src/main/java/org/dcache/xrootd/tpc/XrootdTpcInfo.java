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
package org.dcache.xrootd.tpc;

import com.google.common.base.Strings;

import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * <p>Metadata established via interaction with client, source and
 *    destination in a third-party copy.  Used to verify and
 *    coordinate the open and close requests.</p>
 */
public class XrootdTpcInfo {
    /**
     * <p>Opaque string name-value keys.</p>
     */
    public static final String STAGE = "tpc.stage";

    public static final String RENDEZVOUS_KEY = "tpc.key";

    public static final String SRC = "tpc.src";

    public static final String DST = "tpc.dst";

    public static final String LOGICAL_NAME = "tpc.lfn";

    public static final String CLIENT = "tpc.org";

    public static final String CHECKSUM = "tpc.cks";

    public static final String TIME_TO_LIVE = "tpc.ttl";

    public static final String SIZE_IN_BYTES = "oss.asize";

    /**
     * <p>Opaque string name-value constant values.</p>
     */
    public static final String PLACEMENT = "placement";

    public static final String COPY = "copy";

    public static final String ADLER32 = "adler32";

    public static final String CRC32 = "crc32";

    public static final String MD5 = "md5";

    public enum Status
    {
        PENDING, READY, CANCELLED
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
     * <p>The hostname of the destination server.</p>
     */
    private String dst;

    /**
     * <p>The hostname of the source server.</p>
     */
    private String src;

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

    public XrootdTpcInfo(String key)
    {
        this.key = key;
        this.createdTime = System.currentTimeMillis();
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
        String asize = opaque.get(SIZE_IN_BYTES);
        if (asize != null) {
            this.asize = Long.parseLong(asize);
        }
        status = Status.READY;
    }

    /**
     * <p>Used in a two-phase sequence (client, server),
     *    to add information incrementally.</p>
     *
     * <p>Will not overwrite existing non-null values.</p>
     */
    public XrootdTpcInfo addInfoFromOpaque(String slfn,
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

        return this;
    }

    public Status verify(String dst, String slfn, String org)
    {
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

    public String toString()
    {
        return new StringBuilder().append("(key ")
                                  .append(key)
                                  .append(")(dst ")
                                  .append(dst)
                                  .append(")(src ")
                                  .append(src)
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
                                  .append(")(status ")
                                  .append(status)
                                  .append(")")
                                  .toString();
    }

    public boolean isExpired()
    {
        return ttl != null && System.currentTimeMillis()
                        > (startTime + TimeUnit.SECONDS.toMillis(ttl));
    }

    public long getAsize() {
        return asize;
    }

    public String getCks() {
        return cks;
    }

    public long getCreatedTime() { return createdTime; }

    public String getDst() {
        return dst;
    }

    public Integer getSrcPort() { return srcPort; }

    public int getFd() {
        return fd;
    }

    public String getKey() {
        return key;
    }

    public String getLfn() {
        return lfn;
    }

    public String getOrg() {
        return org;
    }

    public String getSrc() {
        return src;
    }

    public Status getStatus() {
        return status;
    }

    public Long getTtl() {
        return ttl;
    }

    public void setAsize(long asize) {
        this.asize = asize;
    }

    public void setCks(String cks) {
        this.cks = cks;
    }

    public void setDst(String dst) {
        this.dst = dst;
    }

    public void setFd(int fd) {
        this.fd = fd;
    }

    public void setLfn(String lfn) {
        this.lfn = lfn;
    }

    public void setOrg(String org) {
        this.org = org;
    }

    public void setSrc(String src) {
        this.src = src;
    }

    public void setSrcPort(Integer srcPort) { this.srcPort = srcPort; }

    public void setStatus(Status status) {
        this.status = status;
    }

    public void setTtl(Long ttl) {
        this.ttl = ttl;
    }

    private void setSourceFromOpaque(Map<String, String> map)
    {
        this.src = map.get(SRC);
        if (this.src != null) {
            String[] source = this.src.split(":");
            this.src = source[0];
            if (Strings.emptyToNull(source[1]) != null) {
                this.srcPort = Integer.parseInt(source[1]);
            }
        }
    }
}
