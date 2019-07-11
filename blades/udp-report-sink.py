import os, sys, asyncio, socket, struct, binascii, time

err_fmt = lambda err: '[{}] {}'.format(err.__class__.__name__, err)


class UDPRSConf:

	host = '127.0.0.1:1234'
	port = ''
	host_af = 0
	recv_timeout = 5 * 60.0

	### Single report is reassembed from frames with same uid
	### Can have some bits masked to specific values to filter-out junk packets from logs
	### Such filtering is not for security, just to avoid logging random internet noise
	uid_len = 8 # bytes for random uid
	uid_mask_intervals = '3,9,7,6' # csv intervals to check bits at, last one repeated
	uid_mask_bits = '--x--xx-x-' # bits at intervals to match, dash=0 x=1

	# XXX: crypto parameters


class UDPReportSink:

	def __init__(self, iface):
		self.loop, self.conf = ( iface.loop,
			iface.read_conf_section('udp-report-sink', UDPRSConf) )
		self.iface, self.log = iface, iface.get_logger('udprs')

	async def __aenter__(self):
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

		self.frags = dict()
		self.conn_id = self.iface.lib.str_hash(os.urandom(8), 3, key='udprs-1')
		self.log_proto = self.iface.get_logger('udprs', proto=True)

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
		for uid, entry in list(self.frags.items()):
			if entry.ts > ts_cutoff: break
			self.frags.pop(uid)

		# Fragment processing
		seq, final = int.from_bytes(seq, 'big'), False
		if seq & 0x8000: final, seq = True, seq - 0x8000
		addr_str, uid_str = ':'.join(map(str, addr[:2])), binascii.b2a_hex(uid).decode()
		self.log_proto.debug('', extra=( '<< ',
			f'{addr_str} :: {uid_str} :: {seq:02d} {" " if not final else "F"} {len(data)}' ))
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
		if self.parse(addr_str, uid_str, buff): self.send_ack(uid, addr)

	def parse(self, addr_str, uid_str, buff):
		# XXX: decryption here
		print(f'------- msg from={addr_str} uid={uid_str} buff-len={len(buff)}')

	def send_ack(self, uid, addr):
		# XXX: sign uid + nonce here
		print(f'------- ack to={addr} uid={uid}')
		# self.transport.sendto(uid, addr)


# Any last assignment will be used as an entry point
blade_init = UDPReportSink
