/**
 * Logback: the reliable, generic, fast and flexible logging framework.
 * Copyright (C) 1999-2023, QOS.ch. All rights reserved.
 *
 * This program and the accompanying materials are dual-licensed under
 * either the terms of the Eclipse Public License v1.0 as published by
 * the Eclipse Foundation
 *
 *   or (per the licensee's choosing)
 *
 * under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation.
 */
package ch.qos.logback.core.net;

import ch.qos.logback.core.util.EnvUtil;

import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * HardenedObjectInputStream restricts the set of classes that can be deserialized to a set of
 * explicitly whitelisted classes. This prevents certain type of attacks from being successful.
 *
 * <p>A small set of individually enumerated classes from the "java.lang" and "java.util"
 * packages are authorized. Prior versions authorized any class whose name started with
 * "java.lang" or "java.util", which admitted dangerous classes such as
 * java.lang.ProcessBuilder (CVE-2026-9828). Authorization is now performed by exact class
 * name match.</p>
 *
 * @author Ceki G&uuml;lc&uuml;
 * @since 1.2.0
 */
public class HardenedObjectInputStream extends ObjectInputStream {

    final List<String> whitelistedClassNames;
    // CVE-2026-9828: classes in java.lang and java.util are whitelisted individually
    // (exact match) rather than by package prefix. Ported from upstream commit 12cf2c5a.
    final static String[] JAVA_CLASSES = new String[] { "java.lang.Boolean",
            "java.lang.Byte",
            "java.lang.Character",
            "java.lang.Double",
            "java.lang.Float",
            "java.lang.Integer",
            "java.lang.Long",
            "java.lang.Number",
            "java.lang.Short",
            "java.lang.String",
            "java.lang.Throwable",
            "java.util.ArrayList",
            "java.util.Collections$EmptyMap",
            "java.util.Collections$UnmodifiableMap",
            "java.util.concurrent.CopyOnWriteArrayList",
            "java.util.HashMap"
    };
    final private static int DEPTH_LIMIT = 16;
    final private static int ARRAY_LIMIT = 10000;

    public HardenedObjectInputStream(InputStream in, String[] whilelist) throws IOException {
        super(in);
        initObjectFilter();
        this.whitelistedClassNames = new ArrayList<String>();
        if (whilelist != null) {
            for (int i = 0; i < whilelist.length; i++) {
                this.whitelistedClassNames.add(whilelist[i]);
            }
        }
    }

    public HardenedObjectInputStream(InputStream in, List<String> whitelist) throws IOException {
        super(in);
        initObjectFilter();
        this.whitelistedClassNames = new ArrayList<String>();
        this.whitelistedClassNames.addAll(whitelist);
    }

    private void initObjectFilter() {

        // invoke the following code by reflection
        //  this.setObjectInputFilter(ObjectInputFilter.Config.createFilter(
        //                "maxarray=" + ARRAY_LIMIT + ";maxdepth=" + DEPTH_LIMIT + ";"
        //        ));
        if(EnvUtil.isJDK9OrHigher()) {
            try {
                ClassLoader classLoader = this.getClass().getClassLoader();

                Class oifClass = classLoader.loadClass("java.io.ObjectInputFilter");
                Class oifConfigClass = classLoader.loadClass("java.io.ObjectInputFilter$Config");
                Method setObjectInputFilterMethod = this.getClass().getMethod("setObjectInputFilter", oifClass);

                Method createFilterMethod = oifConfigClass.getMethod("createFilter", String.class);
                Object filter = createFilterMethod.invoke(null, "maxarray=" + ARRAY_LIMIT + ";maxdepth=" + DEPTH_LIMIT + ";");
                setObjectInputFilterMethod.invoke(this, filter);
            } catch (ClassNotFoundException e) {
                // this code should be unreachable
                throw new RuntimeException("Failed to initialize object filter", e);
            } catch (InvocationTargetException e) {
                // this code should be unreachable
                throw new RuntimeException("Failed to initialize object filter", e);
            } catch (NoSuchMethodException e) {
                // this code should be unreachable
                throw new RuntimeException("Failed to initialize object filter", e);
            } catch (IllegalAccessException e) {
                // this code should be unreachable
                throw new RuntimeException("Failed to initialize object filter", e);
            }
        }
    }
    @Override
    protected Class<?> resolveClass(ObjectStreamClass anObjectStreamClass) throws IOException, ClassNotFoundException {
        
        String incomingClassName = anObjectStreamClass.getName();
        
        if (!isWhitelisted(incomingClassName)) {
            throw new InvalidClassException("Unauthorized deserialization attempt", anObjectStreamClass.getName());
        }

        return super.resolveClass(anObjectStreamClass);
    }

    /**
     * There is no reason to have proxy classes in logback deserialization, so we just
     * throw an exception here to prevent any potential bypasses that could be achieved
     * through proxy classes (CVE-2026-9828). Ported from upstream commit f7a0654c.
     */
    @Override
    protected Class<?> resolveProxyClass(String[] interfaces) throws IOException, ClassNotFoundException {
        throw new InvalidClassException("Unauthorized deserialization attempt ", Arrays.toString(interfaces));
    }

    private boolean isWhitelisted(String incomingClassName) {
        for (String javaClass : JAVA_CLASSES) {
            if (incomingClassName.equals(javaClass))
                return true;
        }
        for (String whiteListed : whitelistedClassNames) {
            if (incomingClassName.equals(whiteListed))
                return true;
        }
        return false;
    }

    protected void addToWhitelist(List<String> additionalAuthorizedClasses) {
        whitelistedClassNames.addAll(additionalAuthorizedClasses);
    }
}
