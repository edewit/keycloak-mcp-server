package com.github.thomasdarimont.keycloak.mcp.keycloak;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import com.github.thomasdarimont.keycloak.mcp.config.PrivateHosts;

/**
 * Resolves the host of a Keycloak URL and says whether it points into a private network:
 * loopback, link-local, site-local ({@code 10/8}, {@code 172.16/12}, {@code 192.168/16}),
 * carrier-grade NAT ({@code 100.64/10}), unique local IPv6 ({@code fc00::/7}),
 * unspecified, multicast and reserved ranges. Used for systems that arrive at runtime,
 * where the URL is data from a caller rather than the operator's configuration.
 */
public final class HostAddressCheck {

    private HostAddressCheck() {
    }

    /**
     * Why the URL may not be used as a dynamic system under the setting, empty when it
     * may: {@link PrivateHosts#ALLOW} accepts everything; {@link PrivateHosts#LISTED}
     * refuses a host that resolves to a private address unless {@code allowed} names it
     * literally.
     */
    public static Optional<String> refuse(String url, HostAllowList allowed, PrivateHosts setting) {
        if (setting == null || setting == PrivateHosts.ALLOW) {
            return Optional.empty();
        }
        if (allowed != null && allowed.namesLiterally(url)) {
            return Optional.empty();
        }
        return privateAddress(url).map(where -> "The url " + url + " resolves to " + where
                + " (kc-mcp.dynamic-private-hosts=listed): a system registered at runtime may only reach a private"
                + " address when kc-mcp.allowed-hosts names its host literally, without a wildcard.");
    }

    /**
     * The private address the URL's host resolves to, as {@code 10.0.0.5 (site-local)},
     * or the reason it cannot be resolved; empty for a public address.
     */
    public static Optional<String> privateAddress(String url) {
        URI uri;
        try {
            uri = URI.create(url.trim());
        }
        catch (IllegalArgumentException e) {
            return Optional.of("no valid host");
        }
        String host = uri.getHost();
        if (host == null || host.isBlank()) {
            return Optional.of("no valid host");
        }
        InetAddress[] addresses;
        try {
            addresses = InetAddress.getAllByName(stripBrackets(host));
        }
        catch (UnknownHostException e) {
            return Optional.of("an unknown host");
        }
        List<String> hits = new ArrayList<>();
        for (InetAddress a : addresses) {
            String kind = privateKind(a);
            if (kind != null) {
                hits.add(a.getHostAddress() + " (" + kind + ")");
            }
        }
        return hits.isEmpty() ? Optional.empty() : Optional.of(String.join(", ", hits));
    }

    /** The kind of private address, or {@code null} for a public one. */
    public static String privateKind(InetAddress a) {
        if (a.isLoopbackAddress()) {
            return "loopback";
        }
        if (a.isAnyLocalAddress()) {
            return "unspecified";
        }
        if (a.isLinkLocalAddress()) {
            return "link-local";
        }
        if (a.isSiteLocalAddress()) {
            return "site-local";
        }
        if (a.isMulticastAddress()) {
            return "multicast";
        }
        byte[] b = a.getAddress();
        if (a instanceof Inet4Address) {
            int first = b[0] & 0xff;
            int second = b[1] & 0xff;
            if (first == 0) {
                return "this network";
            }
            if (first == 100 && second >= 64 && second <= 127) {
                return "shared address space";
            }
            if (first == 192 && second == 0 && (b[2] & 0xff) == 0) {
                return "IETF protocol assignments";
            }
            if (first == 198 && (second == 18 || second == 19)) {
                return "benchmarking";
            }
            if (first >= 240) {
                return "reserved";
            }
        }
        else if (a instanceof Inet6Address) {
            int first = b[0] & 0xff;
            if ((first & 0xfe) == 0xfc) {
                return "unique local";
            }
            if (first == 0x20 && (b[1] & 0xff) == 0x01 && (b[2] & 0xff) == 0x0d && (b[3] & 0xff) == 0xb8) {
                return "documentation";
            }
        }
        return null;
    }

    private static String stripBrackets(String host) {
        return host.startsWith("[") && host.endsWith("]") ? host.substring(1, host.length() - 1) : host;
    }
}
