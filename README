tranSOCKS_ev - libevent-based, non-forking and transparent SOCKS5-Proxy

Introduction
------------

tranSOCKS_ev is a transparent socks proxy, inspired by the idea of
transocks (http://transocks.sourceforge.net).

In some cases you might redirect TCP/IP-Traffic on your network-router
trough a transparent SOCKS-Proxy. tranSOCKS_ev is a user-space daemon for
linux that does this job perfectly based on iptable-filter-rules.


Installation
------------

tranSOCKS_ev depends on libevent, which is available at
http://monkey.org/~provos/libevent/.

tranSOCKS_ev can be build by typing "make" in the source-directory.
If your libevent wasn't installed at the standard-location you might
adjuist the values specified in Makefile.

Usage
-----

Run transocks_ev from whereever you keep it.

tranSOCKS_ev takes the following options:

	-p Port		The local port where tranSOCKS_ev should listen
			for incoming connections
	-H IP		The local IP-Address where tranSOCKS_ev should
			bind to

	-s Port		The Port of your SOCKS5-Server
	-S IP		The IP-Address of your SOCKS5-Server

	-f		Keep the application in foreground
	-t		Pass through connections through if SOCKS5-Server
			down
	-v		Increase verbosity (may be used multiple times)
	-c Timeout	Timeout connections to SOCKS5-Server after this
			amount of seconds

	-u uid		Drop privileges to this User ID
	-g gid		Drop privileges to this Group ID

	-P pid-file	Write PID-File to this location
	
	-h		Display all available switches

tranSOCKS_ev depends on iptables (as available in most current
linux-distributions) to redirect all traffic that should be
proxied to the transparent proxy.

You will need to setup your firewall on your own because nobody
can guess your special needs.
You may use a script like this:

#!/bin/bash

# Where to find iptables
IPTABLES="/sbin/iptables"

# Port that is transocks listening on
TRANSOCKS_PORT="1211"

# Location of our SOCKS-server
SOCKS_HOST="127.0.0.1"
SOCKS_PORT="5080"

# Create our own chain
$IPTABLES -t nat -N transocks

# Do not try to redirect local traffic
$IPTABLES -t nat -I transocks -o lo -j RETURN

# Do not redirect traffic for the SOCKS-Server
$IPTABLES -t nat -I transocks -p tcp -d $SOCKS_HOST --dport $SOCKS_PORT \
  -j RETURN

# Redirect all traffic that gets to the end of our chain
$IPTABLES -t nat -A transocks -p tcp -j REDIRECT --to-port $TRANSOCKS_PORT

# ---------------
# Tell iptables which traffic acutally to filter
# (just branch into the "transocks"-chain)

# Filter all traffic from the own host
# BE CAREFULL HERE IF THE SOCKS-SERVER RUNS ON THIS MASCHINE
$IPTABLES -t nat -A OUTPUT -j transocks

# Filter all traffic that is routed over this host
$IPTABLES -t nat -A PREROUTING -j transocks



Contact
-------

tranSOCKS_ev is being developed at tiggersWelt.net.
You may send bug reports, ideas and patches to

  bernd@tiggerswelt.net

Check out the tranSOCKS_ev SVN at

  http://oss.tiggerswelt.net/transocks_ev/


Contributors
------------

Chase Venters <chase.venters@gmail.com>
 + Added Support for DNS
 + connect() works asyncronous
 + Improved stability
 + Improved performance, everything is now non-blocking
 + Better logging-support

Karsten N.
 + Wrote initial version of the man-file

Silas S. Brown
 + Suggested a fix for an issue with modern versions of gcc

Toni Spets
 + Pass-through-mode when SOCKS5-Server is down
 + Privilege-Dropping
 + Write PID-File

Licensing
---------

tranSOCKS_ev is distributed within the terms of
creative commons attribution-share alike 3.0 germany.

See http://creativecommons.org/licenses/by-sa/3.0/ for more information
