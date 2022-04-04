/**
 * Copyright (C) 2011-2022 dCache.org <support@dcache.org>
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
package org.dcache.xrootd.plugins.authn.gsi;

import io.netty.buffer.ByteBuf;
import org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType;

/**
 * An XrootdBucket is a serialized datatype (string, uint, binary, list) with
 * an int32 header describing its contents. The headers are well defined and
 * for each header it is known which datatype to expect.
 *
 *
 * @author radicke
 * @author tzangerl
 *
 */
public abstract class GSIBucket {

    protected final BucketType _type;

    public GSIBucket(BucketType type) {
        _type = type;
    }

    /**
     *  This usually will be called only if trace is enabled.
     *
     *  We here imitate the XrootD XrdSutBuffer DUMP printout.
     */
    public int dump(StringBuilder builder, String step, int number) {
        builder.append("\n//                                                    //\n");
        builder.append("//                       GSIBucket                      //\n");
        builder.append("//                                                      //\n");
        builder.append("//  Name: ").append(this.getClass().getSimpleName()).append("\n");
        builder.append("//  Step: ").append(step).append("\n");
        builder.append("//  Buck: ").append(number).append("\n");
        builder.append("//  Type: ").append(_type.name()).append("\n");
        builder.append("//  Size: ").append(getSize()).append("\n");
        return number;
    }

    public BucketType getType() {
        return _type;
    }

    public void serialize(ByteBuf out) {
        out.writeInt(_type.getCode());
    }

    /**
     * @return Length of the serialized bucket (in bytes)
     */
    public int getSize() {
        return 4;
    }

    @Override
    public String toString() {
        return "bucket type: " + _type + "\n";
    }
}

