package com.shieldsvpn.vpn

import org.json.JSONArray
import org.json.JSONObject

/** An address or network in CIDR form, as numeric literals only (never a host name: no DNS lookups). */
data class IpPrefix(val address: String, val prefix: Int) {
    val isV6: Boolean get() = address.contains(':')
    override fun toString() = "$address/$prefix"
}

/**
 * Interface settings for `VpnService.Builder`, parsed from `android_client.tunnel_settings()` output.
 *
 * Python already validated them against the client certificate; this second check makes sure nothing
 * malformed ever reaches the Builder (which would throw, or worse, silently configure something else).
 */
data class TunnelConfig(
    val session: String,
    val mtu: Int,
    val addresses: List<IpPrefix>,
    val routes: List<IpPrefix>,
    val dns: List<String>,
    val fullTunnel: Boolean,
    /** Families with no tunnel address that keep using the normal network (split tunnel). */
    val bypassFamilies: Set<String>,
    /** Families with no tunnel address that are blocked so they cannot leak (full tunnel). */
    val blockedFamilies: Set<String>,
) {
    companion object {
        private val V4 = Regex("""^\d{1,3}(\.\d{1,3}){3}$""")
        private val V6 = Regex("""^[0-9A-Fa-f:.]{2,45}$""")
        private val FAMILIES = setOf("ipv4", "ipv6")

        fun isIpLiteral(s: String): Boolean =
            (V4.matches(s) && s.split('.').all { it.toInt() <= 255 }) ||
                (s.count { it == ':' } >= 2 && V6.matches(s))

        fun fromJson(json: String): TunnelConfig {
            val o = JSONObject(json)
            val mtu = o.getInt("mtu")
            require(mtu in 1280..9000) { "MTU $mtu out of range" }
            val addresses = prefixes(o.getJSONArray("addresses"))
            require(addresses.isNotEmpty()) { "no tunnel address" }
            require(addresses.all { it.prefix > 0 }) { "a tunnel address has a /0 prefix" }
            val routes = prefixes(o.getJSONArray("routes"))
            require(routes.isNotEmpty()) { "no routes" }
            val dns = strings(o.getJSONArray("dns"))
            require(dns.all(::isIpLiteral)) { "invalid DNS server" }
            val bypass = strings(o.optJSONArray("bypass_families") ?: JSONArray()).toSet()
            val blocked = strings(o.optJSONArray("blocked_families") ?: JSONArray()).toSet()
            require(FAMILIES.containsAll(bypass) && FAMILIES.containsAll(blocked)) { "unknown address family" }
            require(bypass.intersect(blocked).isEmpty()) { "a family cannot be both blocked and bypassed" }
            val families = addresses.map { if (it.isV6) "ipv6" else "ipv4" }.toSet()
            require(bypass.none { it in families } && blocked.none { it in families }) {
                "a configured family cannot bypass or be blocked"
            }
            return TunnelConfig(
                session = o.optString("session", "ShieldsVPN").ifBlank { "ShieldsVPN" },
                mtu = mtu,
                addresses = addresses,
                routes = routes,
                dns = dns,
                fullTunnel = o.optBoolean("full_tunnel", false),
                bypassFamilies = bypass,
                blockedFamilies = blocked,
            )
        }

        private fun prefixes(a: JSONArray): List<IpPrefix> = (0 until a.length()).map { i ->
            val p = a.getJSONObject(i)
            val addr = p.getString("address")
            val len = p.getInt("prefix")
            require(isIpLiteral(addr)) { "not an IP address: $addr" }
            require(len in 0..(if (addr.contains(':')) 128 else 32)) { "bad prefix length /$len for $addr" }
            IpPrefix(addr, len)
        }

        private fun strings(a: JSONArray): List<String> = (0 until a.length()).map { a.getString(it) }
    }
}
