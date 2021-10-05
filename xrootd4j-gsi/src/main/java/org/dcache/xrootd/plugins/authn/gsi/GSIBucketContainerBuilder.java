/**
 * Copyright (C) 2011-2021 dCache.org <support@dcache.org>
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

import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Convenience utility for building bucket containers.
 */
public abstract class GSIBucketContainerBuilder {

    private static final Logger LOGGER
          = LoggerFactory.getLogger(GSIBucketContainerBuilder.class);

    /**
     * @param buckets null bucket values are allowed
     * @return the container with all non-null buckets added
     */
    public static GSIBucketContainer build(GSIBucket... buckets) {
        int responseLength = 0;
        List<GSIBucket> responseList = new ArrayList<>();
        for (GSIBucket bucket : buckets) {
            if (bucket != null) {
                responseList.add(bucket);
                responseLength += bucket.getSize();
                LOGGER.trace("added bucket {} of size {}; "
                            + "response length is now {}.",
                      bucket.getType(),
                      bucket.getSize(),
                      responseLength);
            }
        }
        return new GSIBucketContainer(responseList, responseLength);
    }

    public abstract GSIBucketContainer buildContainer();
}
