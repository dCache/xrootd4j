Channel handler plugin for xrootd4j and dCache
==============================================

This is a channel handler plugin for xrootd4j and dCache.

To compile the plugin, run:

    mvn package


The plugin can be tested by loading it with the xrootd4j standalone
server available from http://github.com/dcache/xrootd4j:

    java -Dlog=debug
         -jar /path/to/xrootd4j/xrootd4j-standalone-${xrootd4j}-jar-with-dependencies.jar \
         --plugins target/${artifactId}-${version}/ \
         --handler authn:none,${name}
