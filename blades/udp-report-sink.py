import os, sys, asyncio, socket, struct, binascii, hashlib, time


class UDPRSConf:

	# Bind host, port, address-family (for hostname, 0=any).
	host = '127.0.0.1:1234'
	port = ''
	host_af = 0

	recv_timeout = 8 * 60.0 # for multi-packet msgs, log errs if all fail to arrive in time
	recv_ts_skew = 5 * 60.0 # discards msgs with too-old timestamps in them - can be replays

	# If received packet starts with hb_magic, heartbeat-interval check gets created.
	# hb-packets should unpack to "hb_interval || err_count" values,
	#  which determine when to expect next/follow-up packet(s) (should be constant),
	#  and report any err_count mismatch wrt received report count from that pubkey.
	# hb_check_interval / hb_check_grace_factor is interval between checks for all used
	#  hb-timers, and reporting warnings about any missed ones (with grace_factor slack).
	hb_magic = b'\0hb\0'
	hb_data = struct.Struct('>IQ')
	hb_check_interval = 30 * 60
	hb_check_grace_factor = 4.3

	cb_key = '' # server's private 25519 key, must be specified
	topic = 'udp-report-sink [{conf.host}:{conf.port}]' # channel topic
	nick = 'ursa' # bot nick used to relay msgs from

	# Single report is reassembed from frames with same uid.
	# Can have some bits masked to specific values to filter-out junk packets from logs.
	# Such filtering is not for security, to avoid warn-logging random internet noise.
	uid_len = 8 # bytes for random uid
	uid_mask_intervals = '3,9,7,6' # csv of intervals to check bits at, last one repeated
	uid_mask_bits = '--x--xx-x-' # bits at intervals to match, dash=0 x=1

	# See also: udp-report-sink-chans mapping of chans to keys/topics.


class NaCl:

	nonce_size = key_size = key_encode = key_decode = random = error = None

	def __init__(self):
		libnacl = nacl = None
		try: import libnacl
		except ImportError:
			try: import nacl
			except ImportError:
				raise ImportError( 'Either libnacl or pynacl module'
					' is required for this tool, neither one can be imported.' )

		if libnacl:
			import base64
			from libnacl.secret import SecretBox
			self.nonce_size = libnacl.crypto_secretbox_NONCEBYTES
			self.key_size = libnacl.crypto_secretbox_KEYBYTES
			self.key_encode = lambda key: base64.urlsafe_b64encode(key.sk).decode()
			self.key_decode = lambda key_str, raw=False:\
				SecretBox(key_str if raw else base64.urlsafe_b64decode(key_str))
			self.cb_keygen_seed = libnacl.crypto_box_seed_keypair
			self.cb = ( lambda msg, nonce, pk, sk:
				nonce + libnacl.crypto_box(msg, nonce, pk, sk) )
			self.cb_open = ( lambda buff, pk, sk:
				libnacl.crypto_box_open(buff[self.nonce_size:], buff[:self.nonce_size], pk, sk) )
			self.random = libnacl.randombytes
			self.error = libnacl.CryptError

		if nacl:
			import warnings
			with warnings.catch_warnings(record=True): # cffi warnings
				from nacl.exceptions import CryptoError
				from nacl.encoding import RawEncoder, URLSafeBase64Encoder
				from nacl.public import PrivateKey, PublicKey, Box
				from nacl.secret import SecretBox
				from nacl.utils import random
			self.nonce_size = SecretBox.NONCE_SIZE
			self.key_size = SecretBox.KEY_SIZE
			self.key_encode = lambda key: key.encode(URLSafeBase64Encoder).decode().strip()
			self.key_decode = lambda key_str, raw=False:\
				SecretBox(key_str, URLSafeBase64Encoder if not raw else RawEncoder)
			def _cb_keygen_seed(seed):
				sk = PrivateKey.from_seed(seed)
				return bytes(sk.public_key), bytes(sk)
			self.cb_keygen_seed = _cb_keygen_seed
			self.cb = lambda msg, nonce, pk, sk: Box(PrivateKey(sk), PublicKey(pk)).encrypt(msg, nonce)
			self.cb_open = lambda buff, pk, sk: Box(PrivateKey(sk), PublicKey(pk)).decrypt(buff)
			self.random = random
			self.error = CryptoError

	def test( self, msg=b'test',
			key_enc='pbb6wrDXlLWOFMXYH4a9YHh7nGGD1VnStVYQBe9MyVU=' ):
		# Should run without exceptions and return same consistent hash for both libs
		import hashlib
		key = self.key_decode(self.random(self.key_size), raw=True)
		assert key.decrypt(key.encrypt(msg, self.random(self.nonce_size)))
		key = self.key_decode(key_enc)
		assert self.key_encode(key) == key_enc
		msg_enc = key.encrypt(msg, key_enc[:self.nonce_size].encode())
		msg_dec = key.decrypt(msg_enc)
		assert msg_dec == msg
		(pk1, sk1), (pk2, sk2) = (self.cb_keygen_seed(k) for k in [b'a'*32, b'b'*32])
		nonce = hashlib.sha256(msg).digest()[:self.nonce_size]
		msg_box = self.cb(msg, nonce, pk2, sk1)
		msg_unbox = self.cb_open(msg_box, pk1, sk2)
		assert msg == msg_unbox
		print(hashlib.sha256(b''.join([
			str(self.key_size).encode(), str(self.nonce_size).encode(),
			self.key_encode(key).encode(), msg, msg_enc, msg_dec,
			pk1, sk1, pk2, sk2, nonce, msg_box, msg_unbox ])).hexdigest())

nacl = NaCl()
ts_fmt = lambda ts: time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))


class UDPRSError(Exception): pass

class UDPReportSink:

	def __init__(self, iface):
		self.iface, self.log = iface, iface.get_logger('udprs')
		self.log_proto = iface.get_logger('udprs', proto=True)

	async def __aenter__(self):
		self.conf = self.iface.read_conf_section('udp-report-sink', UDPRSConf)
		chan_info = self.iface.read_conf_section('udp-report-sink-chans').items()
		key_aliases = dict(self.iface.read_conf_section('udp-report-sink-keys').items())

		self.b64dec, self.b64enc = self.iface.lib.b64_decode, self.iface.lib.b64_encode
		self.pkt_header = struct.Struct(f'>{self.conf.uid_len}sH')
		self.box_header = struct.Struct(f'>{self.conf.uid_len}sI')
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
		self.uid_mask = lambda uid: (
			(int.from_bytes(uid, 'big') & ~mask) | mask_val ).to_bytes(8, 'big')
		self.log.debug('uid-mask={:x} uid-mask-val={:x}', mask, mask_val)

		chan_map, self.chan_names, self.chan_keys = dict(), dict(), dict(chan_info)
		chan_key_list, topic_base = dict(), self.conf.topic.format(conf=self.conf)
		for k, v in sorted(self.chan_keys.items(), key=lambda kv: len(kv[0])):
			if k.endswith('.topic'): chan_map[k[:-6]] = self.chan_keys.pop(k)
			elif k.endswith('.nick'): self.chan_names[k[:-5]] = self.chan_keys.pop(k)
			else:
				chan_map[k], self.chan_names[k] = topic_base, self.conf.nick
				for pk in self.chan_keys.pop(k).split():
					if pk.startswith('@'): pk = key_aliases[pk[1:]]
					self.chan_keys[self.b64dec(pk)] = k, pk
					chan_key_list.setdefault(k, list()).append(pk)
		self.iface.reg_chan_map_func(lambda: chan_map)
		for chan, nick in self.chan_names.items(): self.iface.reg_name(chan, nick)

		if not self.conf.cb_key:
			raise ValueError('Local CryptoBox Seed value must be specified in config file')
		self.pk, self.sk = nacl.cb_keygen_seed(self.b64dec(self.conf.cb_key))
		self.log.debug('Local crypto_box pubkey: {}', self.b64enc(self.pk)) # for sender
		for k, pk_list in chan_key_list.items():
			self.log.debug('Channel pubkeys [{}]: {}', k, ' '.join(pk_list))

		self.frags, self.hbs, loop = dict(), dict(), asyncio.get_running_loop()
		sock_t, sock_p, self.conf.host_af, self.conf.host, self.conf.port = \
			self.iface.lib.gai_bind('udp', self.conf.host, self.conf.port, self.conf.host_af, self.log)
		self.transport, proto = await loop.create_datagram_endpoint( lambda: self,
			local_addr=(self.conf.host, self.conf.port), family=self.conf.host_af, proto=sock_p )
		self.hbs_task = loop.create_task(self.hbs_check(
			self.conf.hb_check_interval, self.conf.hb_check_grace_factor ))

	async def __aexit__(self, *err):
		if self.hbs_task: self.hbs_task = await self.iface.lib.aio_task_cancel(self.hbs_task)
		if self.transport: self.transport = self.transport.close()
		self.frags = None

	async def hbs_check(self, interval, grace_factor):
		while True:
			try:
				for pk, hb in self.hbs.items():
					if time.monotonic() - hb.ts_mono < hb.interval * grace_factor: continue
					chan, pk_b64 = self.chan_keys[pk]
					self.iface.send_msg( chan, self.chan_names[chan],
						f'-------- HB-MISSING: pk={pk_b64}'
							f' err-count={hb.err_count} ts-last=[{ts_fmt(hb.ts)}] --------', notice=True )
			except Exception as err: # not checked until shutdown otherwise
				self.log.exception('Heartbeat-check error: {}', self.iface.lib.err_fmt(err))
			await asyncio.sleep(interval)


	def connection_made(self, transport):
		self.log_proto.debug(
			'--- -bind- :: {} {}', self.conf.host, self.conf.port,
			extra=('---', f'bind {self.conf.host} {self.conf.port}') )

	def connection_lost(self, err):
		reason = err or 'closed cleanly'
		if isinstance(reason, Exception): reason = self.iface.lib.err_fmt(reason)
		self.log_proto.debug('--- -close- :: {}', reason, extra=('---', f'close'))

	def datagram_received(self, data, addr):
		# Expected to run on public networks, so obvious junk is dropped silently
		if len(data) < self.pkt_header.size: return
		header, data = data[:self.pkt_header.size], data[self.pkt_header.size:]
		uid_mark, seq = self.pkt_header.unpack(header)
		if not self.uid_match(uid_mark): return

		# Cleanup
		ts_cutoff = time.monotonic() - self.conf.recv_timeout
		for uid_chk, entry in list(self.frags.items()):
			if entry.ts > ts_cutoff: break
			self.frags.pop(uid_chk)
			if entry.get('sent'): continue
			timeout_err = '???'
			if entry.c is None: timeout_err = f'no final frame (total={len(entry)-1})'
			else:
				n = sum(1 for n in range(entry.c + 1) if n in entry)
				if n < entry.c: timeout_err = f'missing frames (recv={n}/{entry.c})'
			self.log.error('Entry timed-out [{}]: {}', self.b64enc(uid_chk), timeout_err)

		# Fragment processing
		if seq & 0x8000: final, seq = True, seq - 0x8000
		else: final = False
		addr_str, uid_str = ':'.join(map(str, addr[:2])), self.b64enc(uid_mark)
		mark, msg = ( '<< ',
			f'{addr_str} :: {uid_str} :: {seq:02d} {" " if not final else "F"} {len(data)}' )
		self.log_proto.debug(f'{mark} {msg}', extra=(mark, msg))
		if uid_mark not in self.frags:
			self.frags[uid_mark] = self.iface.lib.adict(c=None, ts=time.monotonic())
		entry = self.frags[uid_mark]
		if final: entry.c = seq
		replaced, entry[seq] = seq in entry, data
		if entry.c is None or replaced: return

		# Reassembly attempt
		buff = list()
		for n in range(entry.c + 1):
			if n not in entry: return
			buff.append(entry[n])
		entry.sent, buff = True, b''.join(buff)

		# Decrypt/auth/parse and ack
		# Note: frags entry is left as-is until it times-out to avoid re-parsing duplicates
		src_info = self.parse(addr_str, uid_str, uid_mark, buff)
		if src_info:
			pk, uid = src_info
			self.send_ack(addr_str, uid_str, pk, uid, addr)

	def parse(self, addr_str, uid_str, uid_mark, buff):
		for pk, (chan, pk_b64) in self.chan_keys.items():
			try: pkt = nacl.cb_open(buff, pk, self.sk)
			except nacl.error: continue
			break
		else: return self.log.error( 'No key to decode'
			' msg: addr={} uid={} len={}', addr_str, uid_str, len(buff) )

		try:
			if len(pkt) < (n := self.box_header.size): raise UDPRSError('too short')
			header, pkt = pkt[:n], pkt[n:]
			uid, ts = self.box_header.unpack(header)
			if self.uid_mask(uid) != uid_mark: raise UDPRSError('uid mark mismatch')
			if abs(time.time() - ts) >= self.conf.recv_ts_skew:
				raise UDPRSError(f'timestamp mismatch: {ts}')
		except UDPRSError as err:
			return self.log.error( 'Bogus payload (addr={},'
				' uid={}, pk={}): {}', addr_str, uid_str, pk_b64, err )

		if pkt.startswith(self.conf.hb_magic):
			n, fmt = len(self.conf.hb_magic), self.conf.hb_data
			(hb_interval, err_count), pkt = fmt.unpack(pkt[n:n+fmt.size]), pkt[n+fmt.size:]
			hb = self.hbs.get(pk)
			if hb and err_count > hb.err_count:
				err_diff = err_count - hb.err_count
				self.iface.send_msg(
					chan, self.chan_names[chan], '-------- HB-ERR-COUNT:'
						f' pk={pk_b64} err-inc={err_diff} ts-last=[{ts_fmt(hb.ts)}] --------', notice=True )
			self.hbs[pk] = self.iface.lib.adict( ts=time.time(),
				ts_mono=time.monotonic(), interval=hb_interval, err_count=err_count )

		if pkt:
			lines = pkt.decode('utf-8', 'replace')
			self.iface.send_msg(chan, self.chan_names[chan], lines)

		return pk, uid

	def send_ack(self, addr_str, uid_str, pk, uid, addr):
		nonce = os.urandom(nacl.nonce_size)
		buff = nacl.cb(uid, nonce, pk, self.sk)
		mark, msg = ' >>', f'{addr_str} :: {uid_str} :: ack'
		self.log_proto.debug(f'{mark} {msg}', extra=(mark, msg))
		self.transport.sendto(buff, addr)


# Any last assignment will be used as an entry point
blade_init = UDPReportSink
