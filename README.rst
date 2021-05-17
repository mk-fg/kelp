Kelp IRC Daemon
===============

.. contents::
  :backlinks: none

.. image:: https://i.cbc.ca/1.5948104.1615583183!/fileImage/httpImage/image.jpg_gen/derivatives/original_1180/stunning-kelp-forests.jpg
   :width: 100%
   :align: center


Description
-----------

Python3/asyncio daemon to run personal ircd for hosting various other asyncio
code - bots that'd populate its irc channels, most likely with line-based
notifications and reports, as that's what this format is good for.

Based on rdircd_ daemon code and intended to replace `earlier twisted-based bot`_.

It's very much personal helper scripts, so probably only useful to me as-is,
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
as well as server control channels (#kelp.control, #kelp.debug) and catch-all
#kelp.monitor, see topics for more info on these.


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

- udp-report-sink - see UDPRSConf in `udp-report-sink.py <blades/udp-report-sink.py>`_.

- udp-report-sink-chans - channel to source nacl crypto_box pubkeys mapping.

  Each key is a channel name, values are space-separated crypto_box pubkeys or
  @name aliases (from udp-report-sink-keys secion) for all potential sources
  which will be dumped into this channel.

  Special "{chan}.topic" and "{chan}.nick" keys can be used to specify
  topic/nick for each channel, otherwise defauls from UDPRSConf will be used.

- udp-report-sink-keys

  "name = b64(pk)" aliases for source pubkeys, so that any reports about these
  (e.g. missing heartbeats, error count, etc) will have easy-to-read name
  instead of hard-to-remember keys.

Example config for receiver from "some-key-for-A" pubkey into #alpha channel::

  [udp-report-sink]
  host = 0.0.0.0:1234
  ;; uid-mask bits below should results in a
  ;;  pkt[:8] & 0x1008104104104104 == 0x100004100100 filter
  ;; Such filtering is to avoid auth-checking or logging random udp noise
  uid-mask-intervals = 3, 9, 7, 6
  uid-mask-bits = --x--xx-x-
  cb_key = _p0ZbIHfK86H263_DBvaAbyrglrmqhcY0dOBppyPmgU=

  [udp-report-sink-chans]
  alpha = @some-key-for-A
  alpha.topic = Reports from A
  alpha.nick = reporterbot

  [udp-report-sink-keys]
  some-key-for-A = Msf_VdIGWquWN2SwCs9A4hDaE9rBUSkoxWiiOiLCQkY=

See `udp-report-send-test.py <blades/udp-report-send-test.py>`_
for an example of a simple sender script.

logtail
```````

Plugin for tailing a log file (lines of text) in an efficient and reliable
manner into irc channel, remembering last-reported position and handling
rename-rotation (but NOT truncation).

Uses inotify to monitor file(s) for updates and rotation, storing position
and a checksum of last N bytes to a state-file with some rate-limiting
for reads to batch-process frequent messages.

Tailed files are assumed to become static after rotation (filename change)
within specified timeout, after which they're closed and no longer monitored.

Config sections:

- logtail - see LogtailConf in `logtail.py <blades/logtail.py>`_.

- logtail-files - mapping between monitored files and channels.

  Each key is a channel name, values are space-separated file paths to monitor.
  Weird filenames can be urlencoded (decoded via urllib.parse.unquote).

  Special "{chan}.topic" and "{chan}.nick" keys can be used to specify
  topic/nick for each channel, otherwise defauls from LogtailConf will be used.

- logtail-files-proc - regexp-rules for processing individual log lines.

  All rule keys start with arbitrary prefix to group multiple keys, and
  dot-separated suffix after that determines purpose of the value,
  similar to ".topic" and ".nick" for channels above.

  Every rule must have ".file" value to set which file to apply it to,
  and ".re" with python regexp to match each processed line.
  Rules are applied in order they appear in and can affect each other.

  Full list of supported rule-suffixes:

  - file (required) - path used in logtail-files section to apply this rule to.

  - re (required) - regexp to match against each line after str.rstrip()
    (no tailing whitespace, newlines and such) to check if it should be affected
    by this rule. In python's "re" module format.

  - sub - substitution pattern, second argument to python's re.sub().

  - rate-tb - token-bucket rate-limit applied to affected messages.

    | Value format: ``{ interval_seconds: float | float_a/float_b }[:burst_float]``
    | Examples: 1/4:5 (interval=0.25s, rate=4/s, burst=5), 5, 0.5:10, 20:30, 1/2.

    Lines that go over the limit are skipped, with system message printed between
    last passed and first skipped message to indicate when rate-limiting starts.

  - filter - either "blacklist" or "whitelist" to silently drop either all
    matching or non-matching lines respectively.

  See example below for more info.

Example config for a couple logs to a #system channel with some parameters::

  [logtail]
  state-dir = /var/lib/kelp
  read-interval-min = 0.3
  post-rotate-timeout = 1.0

  [logtail-files]
  system = /var/log/kmsg.log /var/log/syslog.log
  system.topic = System log tailer channel
  system.nick = mon

  [logtail-files-proc]

  syslog-clean.file = /var/log/syslog.log
  syslog-clean.re = ^[-\d]{10}T[:\d]{6}(\.\d+)?([-+]\d{2}:\d{2})? (?P<chan>[\w.]+)(<\d+>)? (?P<msg>.*)$
  syslog-clean.sub = \g<chan> \g<msg>

  syslog-selfnoise.file = /var/log/syslog.log
  syslog-selfnoise.re = \skelp\[(\d+|-)\]@\w+:\s
  syslog-selfnoise.rate-tb = 20

Files can be used as simple persistent queues for text messages from anywhere,
and this tailer allows to use those for irc notifications.


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

E.g. ``./kelp -c config.ini -c state.ini`` will do that.
Adding ``--conf-dump`` option will print resulting ini assembled from all these.

Frequent state timestamp updates are done in-place (small fixed-length values),
but checking ctime before writes, so should be safe to tweak any of these files
anytime anyway.

If plugin stores runtime data in ini files, that should be mentioned in its docs.

Channel Commands
````````````````

In special channels like #kelp.control and #kelp.debug:
send "h" or "help", see topic there.

Plugins can react to user messages as well, in their own ways,
which should be documented, if any.

Aliases
```````

Can be defined in the config file to replace hash-based IDs with something
more easily readable::

  [aliases]
  blade.csug = logs

(to turn e.g. #csug.system into #logs.system, and same for other channels of
that plugin)

Currently only implemented for Blade UIDs in IRC channel names.
