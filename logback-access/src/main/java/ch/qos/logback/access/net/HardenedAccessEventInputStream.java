package ch.qos.logback.access.net;

import java.io.IOException;
import java.io.InputStream;

import ch.qos.logback.access.spi.AccessEvent;
import ch.qos.logback.core.net.HardenedObjectInputStream;

public class HardenedAccessEventInputStream extends HardenedObjectInputStream {

    public HardenedAccessEventInputStream(InputStream in) throws IOException {
        super(in, new String[] { AccessEvent.class.getName(), String[].class.getName(),
                // CVE-2026-9828: the core allowlist now matches java.util/java.lang classes by
                // exact name rather than package prefix. A serialized access event's
                // requestHeaderMap is a case-insensitive java.util.TreeMap, which also serializes
                // its comparator (java.lang.String$CaseInsensitiveComparator); authorize both.
                "java.util.TreeMap", "java.lang.String$CaseInsensitiveComparator" });
    }

}
