#!/usr/bin/env python

import os, sys, socket, struct, base64

import libnacl


b64_encode = lambda s: base64.urlsafe_b64encode(s).decode()
b64_decode = lambda s: ( base64.urlsafe_b64decode
	if '-' in s or '_' in s else base64.standard_b64decode )(s)

# seed = os.urandom(32)
# pk, sk = libnacl.crypto_box_seed_keypair(seed)
# print('key:', b64_encode(seed))
# print('pk:', b64_encode(pk))
# print('sk:', b64_encode(sk))
# # key: q7S6eb9dHlLdOi3h-8kgFrzFllxEcR8vqDd50Yj1HcA=
# # pk: qZWtg-jiAzBsTWGKx1YALw_f5nNXYAcG4ClEmhUNdTE=
# # sk: X_2JwsZoF4NDecixg_uCnDB2D4Hi8XWj8S9QZugKV3I=
# exit()


def main():
	dst_addr = '127.0.0.1', 1234
	dst_pk = b64_decode('Msf_VdIGWquWN2SwCs9A4hDaE9rBUSkoxWiiOiLCQkY=')
	src_pk, src_sk = libnacl.crypto_box_seed_keypair(
		b64_decode('q7S6eb9dHlLdOi3h-8kgFrzFllxEcR8vqDd50Yj1HcA=') )
	mtu = 500

	uid_len = 8
	uid_mask = 0x1008104104104104
	uid_mask_val = 0x100004100100

	report = '''
		2019-07-11 13:56:27,728 :: main DEBUG :: Loading blade [blades.udp-report-sink]: blades/udp-report-sink.py
		2019-07-11 13:56:27,733 :: main DEBUG :: Using entry-point [blades.udp-report-sink]: blade_init
		2019-07-11 13:56:27,736 :: main DEBUG :: Resolved host:port '127.0.0.1':6667 [tcp] to endpoint: ('127.0.0.1', 6667) (family: INET, type: STREAM, proto: TCP)
		2019-07-11 13:56:27,736 :: main DEBUG :: Starting eventloop...
		2019-07-11 13:56:27,736 :: asyncio DEBUG :: Using selector: EpollSelector
		2019-07-11 13:56:27,739 :: kelp.blade.udprs DEBUG :: uid-mask=1008104104104104 uid-mask-val=100004100100
		2019-07-11 13:56:27,740 :: kelp.blade.udprs DEBUG :: Resolved host:port '127.0.0.1':1234 [udp] to endpoint: ('127.0.0.1', 1234) (family: INET, type: STREAM, proto: TCP)
		2019-07-11 13:56:27,740 :: proto.blade.udprs DEBUG :: --- -bind- :: 127.0.0.1 1234
		2019-07-11 13:56:27,741 :: kelp.bridge DEBUG :: Starting ircd...
		2019-07-11 13:56:28,467 :: kelp.bridge DEBUG :: Finished
		2019-07-11 13:56:28,467 :: proto.blade.udprs DEBUG :: --- -close- :: closed cleanly'''
	report = ('\n'.join(filter(None, (line.strip() for line in report.split('\n')))) + '\n').encode()

	with socket.socket( socket.AF_INET,
			socket.SOCK_DGRAM, socket.IPPROTO_UDP ) as s:

		pkt_header = struct.Struct(f'>{uid_len}sH')
		data_len = mtu - pkt_header.size
		def data_send(uid, buff):
			n, nonce = 0, os.urandom(24)
			buff = nonce + libnacl.crypto_box(buff, nonce, dst_pk, src_sk)
			while buff:
				frame, buff = buff[:data_len], buff[data_len:]
				frame_n, n = n, n + 1
				if not buff: frame_n |= 0x8000
				frame = pkt_header.pack(uid, frame_n) + frame
				print(f'Frame {frame_n & (0xffff - 0x8000)}: {len(frame)}B')
				s.sendto(frame, dst_addr)
			# Sending should be repeated a few times until it gets ack response

		def data_ack_recv():
			buff, addr = s.recvfrom(65535)
			nonce, buff = buff[:24], buff[24:]
			return libnacl.crypto_box_open(buff, nonce, dst_pk, src_sk)

		gen_uid = lambda: (
			(int.from_bytes(os.urandom(uid_len), 'big') & ~uid_mask)
			| uid_mask_val ).to_bytes(8, 'big')

		### Send/ack report lines

		uid = gen_uid()
		print('uid:', uid)
		data_send(uid, report)
		uid_ack = data_ack_recv()
		print('ack-success' if uid_ack == uid else 'ack-mismatch')

		### Send/ack heartbeats

		interval, err_count = 10, 0

		uid = gen_uid()
		hb = b'\0hb\0' + struct.pack('>IQ', interval, err_count)
		data_send(uid, hb)
		uid_ack = data_ack_recv()
		print('hb-ack-success' if uid_ack == uid else 'hb-ack-mismatch')

		err_count += 123 # should trigger HB-ERR-COUNT notice
		uid = gen_uid()
		hb = b'\0hb\0' + struct.pack('>IQ', interval, err_count)
		data_send(uid, hb)
		uid_ack = data_ack_recv()
		print('hb-ack-success' if uid_ack == uid else 'hb-ack-mismatch')

		# Missing follow-up heartbeats should trigger HB-MISSING notices
		# But note that these are only checked 1/hb_check_interval (e.g. 1/30m)

if __name__ == '__main__': sys.exit(main())
