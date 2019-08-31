# rrdub
RRDtool + ubus
======

A simple connector between
[RRDtool](https://oss.oetiker.ch/rrdtool/) &
[ubus](https://openwrt.org/docs/techref/ubus).
Creates a ubus object (default: `rrd`) bound to a single `rrdcached`
instance & exports
 * `stats`: general statistics for this cache,
 * `list`: list RRD files under management for this cache,
 * `info`: specific information for a particular RRD file, &
 * `fetch`: fetch current buckets for a particular RRD.

Does not currently support creation or updates via ubus.

Requires
 * [librrd](https://github.com/oetiker/rrdtool-1.x "RRDtool 1.x") (GPL2+ with FLOSS exception)
 * [libubus](https://git.openwrt.org/project/ubus.git "OpenWrt system message/RPC bus") (LGPL2.1)
 * [libubox](https://git.openwrt.org/project/libubox.git "C utility functions for OpenWrt") (ISC)

If not using
[glibc](https://www.gnu.org/software/libc/ "The GNU C Library"),
requires external `argp` library, e.g. via
[argp-standalone](https://www.lysator.liu.se/~nisse/misc/).

License: [MIT](https://opensource.org/licenses/MIT)
