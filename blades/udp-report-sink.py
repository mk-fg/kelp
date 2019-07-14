import os, sys, asyncio, socket, struct, binascii, hashlib, time

import libnacl


class UDPRSConf:

	host = '127.0.0.1:1234'
	port = ''
	host_af = 0
	recv_timeout = 5 * 60.0

	cb_key = '' # must be specified
	topic = 'udp-report-sink [{conf.host}:{conf.port}]'
	nick = 'ursa'

	### Single report is reassembed from frames with same uid
	### Can have some bits masked to specific values to filter-out junk packets from logs
	### Such filtering is not for security, just to avoid logging random internet noise
	uid_len = 8 # bytes for random uid
	uid_mask_intervals = '3,9,7,6' # csv intervals to check bits at, last one repeated
	uid_mask_bits = '--x--xx-x-' # bits at intervals to match, dash=0 x=1

	# See also: udp-report-sink-chans mapping of chans to keys/topics.


err_fmt = lambda err: '[{}] {}'.format(err.__class__.__name__, err)


class UDPReportSink:

	def __init__(self, iface):
		self.iface, self.log = iface, iface.get_logger('udprs')
		self.log_proto = iface.get_logger('udprs', proto=True)

	async def __aenter__(self):
		self.loop, self.conf = ( self.iface.loop,
			self.iface.read_conf_section('udp-report-sink', UDPRSConf) )
		chan_info = self.iface.read_conf_section('udp-report-sink-keys').items()

		self.pkt_header = struct.Struct(f'>{self.conf.uid_len}sH')
		bit, bits, bit_max = 0, list(), self.conf.uid_len * 8 - 1
		ns = list(int(n.strip()) for n in self.conf.uid_mask_intervals.split(','))
		if not ns: raise ValueError(self.conf.uid_mask_intervals)
		ns += bit_max * [ns[-1]]
		for n in ns:
			bit += n
			if 0 <= bit <= bit_max: bits.append(bit_max - bit)
		if len(self.conf.uid_mask_bits) != len(bits):
			raise ValueError( 'Bitmask length mismatch:'
				f' calculated={len(bits)} configured={len(self.conf.uid_mask_bits)}' )
		mask = mask_val = 0
		for n, s in zip(bits, self.conf.uid_mask_bits):
			v = 1 << n
			mask += v
			mask_val += (s == 'x') * v
		if mask_val & mask != mask_val: raise RuntimeError
		self.uid_match = lambda uid: int.from_bytes(uid, 'big') & mask == mask_val
		self.log.debug('uid-mask={:x} uid-mask-val={:x}', mask, mask_val)

		b64dec, b64enc = self.iface.lib.b64_decode, self.iface.lib.b64_encode
		chan_map, self.chan_names, self.chan_keys = dict(), dict(), dict(chan_info)
		chan_key_list, topic_base = dict(), self.conf.topic.format(conf=self.conf)
		for k, v in sorted(self.chan_keys.items(), key=lambda kv: len(kv[0])):
			if k.endswith('-topic'): chan_map[k[:-6]] = self.chan_keys.pop(k)
			elif k.endswith('-nick'): self.chan_names[k[:-5]] = self.chan_keys.pop(k)
			else:
				chan_map[k], self.chan_names[k] = topic_base, self.conf.nick
				for pk in self.chan_keys.pop(k).split():
					self.chan_keys[b64dec(pk)] = k
					chan_key_list.setdefault(k, list()).append(pk)
		self.iface.reg_chan_map_func(lambda: chan_map)
		for chan, nick in self.chan_names.items(): self.iface.reg_name(chan, nick)

		if not self.conf.cb_key:
			raise ValueError('Local CryptoBox Seed value must be specified in config file')
		self.pk, self.sk = libnacl.crypto_box_seed_keypair(b64dec(self.conf.cb_key))
		self.log.debug('Local crypto_box pubkey: {}', b64enc(self.pk)) # for sender
		for k, pk_list in chan_key_list.items():
			self.log.debug('Channel pubkeys [{}]: {}', k, ' '.join(pk_list))

		self.frags = dict()
		sock_t, sock_p, self.conf.host_af, self.conf.host, self.conf.port = \
			self.iface.lib.gai_bind('udp', self.conf.host, self.conf.port, self.conf.host_af, self.log)
		self.transport, proto = await self.loop.create_datagram_endpoint( lambda: self,
			local_addr=(self.conf.host, self.conf.port), family=self.conf.host_af, proto=sock_p )

	async def __aexit__(self, *err):
		if self.transport: self.transport = self.transport.close()
		self.frags = None


	def connection_made(self, transport):
		self.log_proto.debug(
			'--- -bind- :: {} {}', self.conf.host, self.conf.port,
			extra=('---', f'bind {self.conf.host} {self.conf.port}') )

	def connection_lost(self, err):
		reason = err or 'closed cleanly'
		if isinstance(reason, Exception): reason = err_fmt(reason)
		self.log_proto.debug('--- -close- :: {}', reason, extra=('---', f'close'))

	def datagram_received(self, data, addr):
		# Expected to run on public networks, so obvious junk is dropped silently
		if len(data) < self.pkt_header.size: return
		header, data = data[:self.pkt_header.size], data[self.pkt_header.size:]
		uid, seq = self.pkt_header.unpack(header)
		if not self.uid_match(uid): return

		# Cleanup
		ts_cutoff = time.monotonic() - self.conf.recv_timeout
		for uid_chk, entry in list(self.frags.items()):
			if entry.ts > ts_cutoff: break
			# XXX: check if it's still incomplete and report error
			self.frags.pop(uid_chk)

		# Fragment processing
		if seq & 0x8000: final, seq = True, seq - 0x8000
		else: final = False
		addr_str, uid_str = ':'.join(map(str, addr[:2])), binascii.b2a_hex(uid).decode()
		mark, msg = ( '<< ',
			f'{addr_str} :: {uid_str} :: {seq:02d} {" " if not final else "F"} {len(data)}' )
		self.log_proto.debug(f'{mark} {msg}', extra=(mark, msg))
		if uid not in self.frags:
			self.frags[uid] = self.iface.lib.adict(c=None, ts=time.monotonic())
		entry = self.frags[uid]
		if final: entry.c = seq
		replaced, entry[seq] = seq in entry, data
		if entry.c is None or replaced: return

		# Reassembly attempt
		buff = list()
		for n in range(entry.c + 1):
			if n not in entry: return
			buff.append(entry[n])
		buff = b''.join(buff)

		# Decrypt/auth/parse and ack
		# Note: frags entry is left as-is until it times-out to avoid re-parsing duplicates
		# XXX: receive heartbeats and track hb-interval info, check remote error counter there
		pk = self.parse(addr_str, uid_str, buff)
		if pk: self.send_ack(addr_str, uid_str, pk, uid, addr)

	def parse(self, addr_str, uid_str, buff):
		nonce, buff = buff[:24], buff[24:]
		for pk, chan in self.chan_keys.items():
			try: lines = libnacl.crypto_box_open(buff, nonce, pk, self.sk)
			except libnacl.CryptError: continue
			lines = lines.decode('utf-8', 'replace')
			self.iface.send_msg(chan, self.chan_names[chan], lines)
			return pk
		else:
			self.log.error( 'No key to decode msg:'
				' addr={} uid={} len={}', addr_str, uid_str, len(buff) )

	def send_ack(self, addr_str, uid_str, pk, uid, addr):
		nonce = os.urandom(24)
		buff = nonce + libnacl.crypto_box(uid, nonce, pk, self.sk)
		mark, msg = ' >>', f'{addr_str} :: {uid_str} :: ack'
		self.log_proto.debug(f'{mark} {msg}', extra=(mark, msg))
		self.transport.sendto(buff, addr)


# Any last assignment will be used as an entry point
blade_init = UDPReportSink
