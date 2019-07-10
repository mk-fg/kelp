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


Requirements
------------

* `Python 3.7+ <http://python.org/>`_


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

| In special channels like #control and #debug: send "h" or "help".

asyncio ERROR :: Fatal read error on socket transport
`````````````````````````````````````````````````````

Rarely this error might pop-up randomly, when websocket connection is patchy::

  asyncio ERROR :: Fatal read error on socket transport
  protocol: <asyncio.sslproto.SSLProtocol object at 0x7f057da99080>
  transport: <_SelectorSocketTransport fd=9 read=polling write=<idle, bufsize=0>>
  Traceback (most recent call last):
    File "/usr/lib/python3.7/asyncio/selector_events.py", line 801, in _read_ready__data_received
      data = self._sock.recv(self.max_size)
  TimeoutError: [Errno 110] Connection timed out

It's a problem in python3 asyncio, as described in `Python Issue 34148`_ and `PR#11576`_.

Should be harmless, especially as both websocket and discord protocols have
built-in keepalives to work around any kind of underlying connection problems.

.. _Python Issue 34148: https://bugs.python.org/issue34148
.. _PR#11576: https://github.com/python/cpython/pull/11576
