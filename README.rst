Kelp IRC Daemon
===============

.. contents::
  :backlinks: none


Description
-----------

Python3/asyncio daemon to run personal ircd for hosting various other asyncio
code - bots that'd populate its irc channels, most likely with line-based
notifications and reports, as that's what this format is good for.

Based on earlier rdircd_ daemon code and intended to replace `earlier twisted-based bot`_.

It's very much personal helper, so porbably only useful to me as-is,
but feel free to use anything here that might be of value otherwise.

.. _rdircd: https://github.com/mk-fg/reliable-discord-client-irc-daemon
.. _earlier twisted-based bot: https://github.com/mk-fg/bordercamp-irc-bot


Usage
-----

There are no script dependencies to install, beyond the basic python 3.x.

Create configuration file with ircd auth credentials and any other settings in
~/.kelp.ini (see all the --conf\* opts wrt these)::

  [irc]
  password = hunter2

Note: IRC password can be omitted, but be sure to firewall that port from
everything in the system then (or maybe do it anyway).

Start kelp daemon: ``./kelp --debug``

Connect IRC client to "localhost:6667" (see ``./kelp --conf-dump-defaults``
or -i/--irc-bind option for using diff host/port).

Run ``/list`` to see channels for all running bots, services and such,
as well as server control channels (#control, #debug) and catch-all #monitor,
see topics for more info on these.


"blade" plugins
---------------

They are actual point of the whole thing.

Enabled like this::

  [blades]
  enabled = udp-report-sink some-other-script

Specified .py files loaded from ``dir =`` (default "blades") and last definition there
is initialized as an async context manager, being passed KelpBladeInterface object.

Each gets short base64 prefix for all channels it generates (based on name),
and can use these (send-to, read, query names) separately from any other loaded blade-scripts.
Can be configured via separate section(s) in the ini file(s).

See scripts in "blades" dir and KelpBladeInterface object for any implementation details.

udp-report-sink
```````````````

Plugin for receiving occasional usually-multiline log errors/warnings
from remote sources to feed them into irc channel(s) as notifications,
picking destination channel based on libnacl crypto_box key used for encryption.

In addition logs missing heartbeats from remote, local/remote error counter
jumps (e.g. due to failed delivery), does auth-encryption via pynacl, etc.

Config sections:

- udp-report-sink - see UDPRSConf.

- udp-report-sink-chans - channel to source nacl crypto_box pubkeys mapping.

  Each key is a channel name, values are space-separated crypto_box pubkeys or
  @name aliases (from udp-report-sink-keys secion) for all potential sources
  which will be dumped into this channel.

  Special "{chan}-topic" and "{chan}-nick" keys can be used to specify
  topic/nick for each channel, otherwise defauls from udp-report-sink will be used.

- udp-report-sink-keys

  "name = b64(pk)" aliases for source pubkeys, so that any reports about these
  (e.g. missing heartbeats, error count, etc) will have easy-to-read name
  instead of hard-to-remember keys.

See blades/udp-report-send-test.py for an example of simple sender script.


Requirements
------------

* `Python 3.7+ <http://python.org/>`_
* [udp-report-sink] `libnacl <https://libnacl.readthedocs.io/en/latest/>`_


Misc Features
-------------

| Notes on various optional and less obvious features are collected here.
| See "Usage" section for a more general information.

Multiple Config Files
`````````````````````

Multiple ini files can be specified with -c option, overriding each other in sequence.

Last one will be updated wrt [state] and similar runtime stuff,
so it can be useful to specify persistent config with auth and options,
and separate (initially empty) one for such dynamic state.

| E.g. ``./kelp -c config.ini -c state.ini`` will do that.
| ``--conf-dump`` can be added to print resulting ini assembled from all these.
|

Frequent state timestamp updates are done in-place (small fixed-length values),
but checking ctime before writes, so should be safe to tweak any of these files
anytime anyway.

Channel Commands
````````````````

In special channels like #control and #debug: send "h" or "help", see topic there.

Plugins can react to user messages as well, in their own ways.

Aliases
```````

Can be defined in the config file to replace hash-based IDs with something
easily readable::

  [aliases]
  blade.cSug = urs

(to turn e.g. #cSug.info into #urs.info)

Currently only implemented for Blade UIDs in IRC channel names.
