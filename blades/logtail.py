import collections as cs, hashlib as hl, pathlib as pl
import ctypes as ct, functools as ft, urllib.parse as up
import os, sys, asyncio, re, enum, struct, errno, zlib, fcntl, termios


class LogtailConf:

	state_dir = '/tmp/kelp-logtail' # one file for each "last position" in a path
	read_size = 1 * 2**20 # chunk to read/process from file
	read_interval_min = 0.1 # rate-limiting delay between update-processing events
	post_rotate_timeout = 3.0 # time to wait between filename change detection and closing file
	track_len = 120 # how many bytes to checksum for tracking position
	inotify_sanity_check_interval = 709 # generate dummy events in case of bugs, 0 - disable
	old_log_suff = '.1 .0 .old .bak' # warn about writes to unmonitored files with these
	old_log_suff_notify_interval = 600

	topic = 'logtail: {tail_files}'
	nick = 'lot'


class INotify:
	class flags(enum.IntEnum): # see "man inotify"
		access = 0x00000001
		modify = 0x00000002
		attrib = 0x00000004
		close_write = 0x00000008
		close_nowrite = 0x00000010
		open = 0x00000020
		moved_from = 0x00000040
		moved_to = 0x00000080
		create = 0x00000100
		delete = 0x00000200
		delete_self = 0x00000400
		move_self = 0x00000800

		unmount = 0x00002000
		q_overflow = 0x00004000
		ignored = 0x00008000

		onlydir = 0x01000000
		dont_follow = 0x02000000
		excl_unlink = 0x04000000
		mask_add = 0x20000000
		isdir = 0x40000000
		oneshot = 0x80000000

		close = close_write | close_nowrite
		move = moved_from | moved_to
		all_events = (
			access | modify | attrib | close_write | close_nowrite | open |
			moved_from | moved_to | delete | create | delete_self | move_self )

		@classmethod
		def unpack(cls, mask):
			return set( flag
				for flag in cls.__members__.values()
				if flag & mask == flag )

	_INotifyEv = struct.Struct('iIII')
	INotifyEv = cs.namedtuple( 'INotifyEv',
		'path path_mask wd flags cookie name' )
	INotifyEvTracker = cs.namedtuple('INotifyCtl', 'add rm ev_iter')

	_libc = None
	@classmethod
	def _get_lib(cls):
		if cls._libc is None: libc = cls._libc = ct.CDLL('libc.so.6', use_errno=True)
		return cls._libc

	def _call(self, func, *args):
		if isinstance(func, str): func = getattr(self._lib, func)
		while True:
			res = func(*args)
			if res == -1:
				err = ct.get_errno()
				if err == errno.EINTR: continue
				else: raise OSError(err, os.strerror(err))
			return res

	def __init__(self): self._lib = self._get_lib()

	def open(self):
		self.fd, self.wd_info = self._call('inotify_init'), dict() # (path, mask, queue)
		asyncio.get_running_loop().add_reader(self.fd, self.read)
		return self
	def close(self):
		for path, mask, queue in self.wd_info.values(): queue.put_nowait(None)
		asyncio.get_running_loop().remove_reader(self.fd)
		self.fd = self.wd_info = os.close(self.fd)
	async def __aenter__(self): return self.open()
	async def __aexit__(self, *err): self.close()

	def read(self):
		bs = ct.c_int()
		fcntl.ioctl(self.fd, termios.FIONREAD, bs)
		if bs.value <= 0: return
		buff = os.read(self.fd, bs.value)
		n, bs = 0, len(buff)
		while n < bs:
			wd, flags, cookie, name_len = self._INotifyEv.unpack_from(buff, n)
			n += self._INotifyEv.size
			name = ct.c_buffer(buff[n:n + name_len], name_len).value.decode()
			n += name_len
			try:
				path, mask, queue = self.wd_info[wd]
				queue.put_nowait(self.INotifyEv(path, mask, wd, flags, cookie, name))
			except KeyError: pass # after rm_watch or IN_Q_OVERFLOW (wd=-1)
		if n != bs:
			log.warning( 'Unused trailing bytes on inotify-fd [{}]: {}',
				(bs := bs - n), ct.c_buffer(buff[n:], bs).value.decode() )

	def get_ev_tracker(self):
		queue = asyncio.Queue()
		def add(path, mask):
			wd = self._call('inotify_add_watch', self.fd, bytes(path), mask)
			self.wd_info[wd] = path, mask, queue
			return wd
		def rm(wd):
			if self.fd:
				self._call('inotify_rm_watch', self.fd, wd)
				self.wd_info.pop(wd)
			os.close(wd)
		async def ev_iter(dummy_first=True, dummy_interval=None):
			if dummy_first: yield # for easy setup-on-first-iter in "async for"
			while True:
				ev = queue.get()
				if dummy_interval: ev = asyncio.wait_for(ev, dummy_interval)
				try: ev = await ev
				except asyncio.TimeoutError: ev = False
				if ev is None: break
				yield ev
		return self.INotifyEvTracker(add, rm, ev_iter)


class LogTailer:

	def __init__(self, iface):
		self.iface, self.log = iface, iface.get_logger('logtail')

	async def __aenter__(self):
		self.conf = self.iface.read_conf_section('logtail', LogtailConf)
		self.inotify = INotify().open()

		self.file_state_dir = pl.Path(self.conf.state_dir)
		self.file_state_dir.mkdir(0o700, parents=True, exist_ok=True)

		chan_map, chan_files = dict(), cs.defaultdict(set)
		self.file_chans, self.chan_names = cs.defaultdict(set), dict()
		for k, v in sorted(self.iface.read_conf_section('logtail-files').items()):
			if k.endswith('.topic'): chan_map[k[:-6]] = v
			elif k.endswith('.nick'): self.chan_names[k[:-5]] = v.strip()
			elif fn_list := sorted(up.unquote(fn) for fn in v.split() if fn):
				chan_map[k] = self.conf.topic.format(tail_files=' '.join(fn_list))
				for fn in fn_list: self.file_chans[pl.Path(fn).resolve()].add(k)
				self.chan_names[k] = self.conf.nick

		self.iface.reg_chan_map_func(lambda: chan_map)
		for chan, nick in self.chan_names.items(): self.iface.reg_name(chan, nick)
		self.iface.reg_main_task(self.run())

		self.proc_rules = dict()
		for k, v in self.iface.read_conf_section('logtail-files-proc').items():
			try:
				name, k = k.split('.', 1)
				if k not in ['file', 're', 'sub', 'rate-tb', 'filter']: raise ValueError(k)
			except ValueError: raise self.iface.error(f'Invalid processing-rule suffix: {k}')
			if name not in self.proc_rules:
				self.proc_rules[name] = self.iface.lib.adict(name=name)
				self.proc_rules[name].update(dict.fromkeys('file re sub rate_tb filter'.split()))
			if k == 'file': v = pl.Path(v).resolve()
			elif k == 're': v = re.compile(v)
			elif k == 'rate-tb': v = self.iface.lib.token_bucket(v)
			elif k == 'filter': v = dict(whitelist=True, blacklist=False)[v.lower()]
			self.proc_rules[name][k.replace('-', '_')] = v
		for rule in self.proc_rules.values():
			if not (rule.file and rule.re):
				raise self.iface.error(f'Processing-rule missing required keys: {rule}')
			if not (rule.sub is not None or rule.rate_tb or rule.filter is not None):
				raise self.iface.error(f'Processing-rule without action: {rule}')

	async def __aexit__(self, *err):
		self.file_state_dir = self.file_chans = self.chan_names = self.proc_rules = None
		self.inotify = self.inotify.close()

	def log_buff_repr(self, buff, n=120):
		if len(buff := buff.strip()) > n:
			buff = '[{}/{}B] {}'.format(n, len(buff), repr(buff[:n]) + '...')
		return buff

	def file_stat_id(self, path_or_file):
		try:
			st = ( os.fstat(path_or_file.fileno())
				if hasattr(path_or_file, 'fileno') else path_or_file.stat() )
		except OSError as err:
			if err.errno != errno.ENOENT: raise
			return
		return st.st_dev, st.st_ino

	async def run_file_tailer(self, file_path, buff_cb):
		'Handles tailing one file_path and calls "buff_leftover = buff_cb(buff)" on new data there.'
		file_path_dir = file_path.resolve().parent
		file_state_id = f'{self.iface.lib.str_hash(file_path_dir, 10)}.{file_path.name}'
		self.log.debug('[{}] Monitoring file: {}', file_state_id, file_path)
		imf, inn = self.inotify.flags, self.inotify.get_ev_tracker()
		loop, task = asyncio.get_running_loop(), asyncio.current_task()

		watch_file = watch_buff = None
		watch_file_tail = watch_file_init = watch_file_timer = None
		def _watch_file_process(bs=self.conf.read_size):
			'Called when any new data might be appended to a file'
			nonlocal watch_buff, watch_file_timer, watch_file_tail
			try:
				if not watch_file_init: _watch_file_track() # rewind to last pos
				while True:
					buff = watch_file.read(bs)
					if not buff: break
					watch_file_tail = (watch_file_tail or b'') + buff
					try: watch_buff = buff_cb(watch_buff + buff)
					except Exception as err:
						self.log.exception( '[{}] Failed to process line-buffer (( {} )), dropping it: {}',
							file_state_id, self.log_buff_repr(watch_buff + buff), self.iface.lib.err_fmt(err) )
						watch_buff = b''
					_watch_file_track()
					if len(buff) != bs: break # EOF
			except Exception as err:
				self.log.exception( '[{}] Failed to process'
					' file updates: {}', file_state_id, self.iface.lib.err_fmt(err) )
				task.cancel()
			finally: watch_file_timer = None

		watch_file_state = self.file_state_dir / f'{file_state_id}.state'
		watch_file_state = os.fdopen(os.open(
			watch_file_state, os.O_RDWR | os.O_CREAT, 0o600 ), 'r+b', 0)
		watch_file_state_fmt = struct.Struct('>LHL') # (pos, len, adler32)
		def _watch_file_track(tbs=self.conf.track_len):
			'Called to rewind file after open(), update state on read, and clear it after rotation'
			nonlocal watch_file_tail, watch_file_init
			watch_file_state.seek(0)
			if not watch_file: watch_file_state.truncate()
			elif not watch_file_init:
				watch_file_init, st = True, watch_file_state.read(watch_file_state_fmt.size)
				if st:
					try: pos, tbs, cksum = watch_file_state_fmt.unpack(st)
					except struct.error: pos = tbs = cksum = 0
					if pos <= 0 or tbs <= 0:
						self.log.warning( '[{}] Corrupted last-file-position'
							' state data, discarding it [ {} ]: {}', file_state_id, st.hex(), file_path )
					else:
						watch_file.seek(max(0, pos - tbs))
						cksum_now = zlib.adler32(watch_file_tail := watch_file.read(tbs))
						# self.log.debug( 'Chunk {} / {} B, {:o} {} {:o}: {!r}', len(watch_file_tail),
						# 	tbs, cksum, '=' if cksum == cksum_now else '!=', cksum_now, watch_file_tail )
						if cksum != cksum_now:
							self.log.warning( '[{}] File contents mismatch at position mark'
								' ({:,d} B), parsing file from the beginning: {}', file_state_id, pos, file_path )
							watch_file_tail = watch_file.seek(0) and None
			else:
				pos = watch_file.tell() - (tl := len(watch_buff))
				watch_file_tail = watch_file_tail[-(tbs+tl):]
				# csum = zlib.adler32(chunk := watch_file_tail[:tbs])
				# self.log.debug('File-state-tail {} / {} B, {:o}: {!r}', len(chunk), tbs, csum, chunk)
				# watch_file_state.write(watch_file_state_fmt.pack(pos, tbs, csum))
				watch_file_state.write( watch_file_state_fmt\
					.pack(pos, tbs, zlib.adler32(watch_file_tail[:tbs])) )

		fn, watch_fd = file_path.name, inn.add(file_path.parent, imf.modify)
		fn_old_ts, fn_old_set = 0, set(f'{fn}{suff}' for suff in self.conf.old_log_suff.split())
		try:
			async for ev in inn.ev_iter(
					dummy_interval=self.conf.inotify_sanity_check_interval ):
				if ev and ev.name != fn: # changes in other files
					if ( ev.name not in fn_old_set or
						fn_old_ts > loop.time() - self.conf.old_log_suff_notify_interval ): continue
					self.log.warning('Detected writes to old/rotated log file: {}', file_path_dir / ev.name)
					fn_old_ts = loop.time()
				# self.log.debug('inotify: {} {}', ev, ev and imf.unpack(ev.flags))

				if not watch_file:
					if not file_path.exists(): continue
					watch_file_new = self.log.debug('Opening log file: {}', file_path.name)
					try:
						watch_file_new = file_path.open('rb')
						watch_file_new_id = self.file_stat_id(watch_file_new)
					except FileNotFoundError:
						if watch_file_new: watch_file_new.close()
						continue # old/repeated event
					else:
						ev, watch_buff, watch_file, watch_file_id = (
							ev and None, b'', watch_file_new, watch_file_new_id )
				elif self.file_stat_id(file_path) != watch_file_id: # file was rotated
					# Wait for any pending writes to finish, process remaining tail here
					# Not tracking close_write as there can potentially be multiple writers
					if watch_file_timer: watch_file_timer = watch_file_timer.cancel()
					if ev is False: self.log.warning('BUG - dummy event triggered file rotation')
					ts_deadline = loop.time() + self.conf.post_rotate_timeout
					for delay in self.iface.lib.retries_within_timeout(4, self.conf.post_rotate_timeout):
						await asyncio.sleep(delay)
						_watch_file_process()
						if loop.time() >= ts_deadline: break
					if watch_buff:
						self.log.warning( '[{}] Incomplete last line at EOF'
							' on closing file: {}', file_state_id, self.log_buff_repr(watch_buff) )
					watch_file = watch_file_id = watch_file_tail = watch_buff = watch_file.close()
					_watch_file_track() # reset tracking pos
					continue

				if not watch_file_timer: # schedule/delay processing file updates
					watch_file_timer = loop.call_later(self.conf.read_interval_min, _watch_file_process)

		finally:
			inn.rm(watch_fd)
			if watch_file: watch_file = watch_file.close()
			if watch_file_state: watch_file_state = watch_file_state.close()

	def proc_file_updates(self, p, chan_set, buff):
		'Process/dispatch any complete lines from buffer as msgs and return leftover bytes'
		try: lines, buff = buff.rsplit(b'\n', 1)
		except ValueError: return buff
		lines = lines.decode(errors='replace')
		for line in map(str.rstrip, lines.split('\n')):
			for name, rule in self.proc_rules.items():
				if rule.file != p: continue
				m = rule.re.search(line)
				if m:
					if rule.sub: line = m.expand(rule.sub)
					if rule.rate_tb:
						block = next(rule.rate_tb)
						if block:
							if not rule.get('rate_tb_block'):
								line += f'\n[started rate-limiting similar messages by rule: {name}]'
							else: line = None
						rule.rate_tb_block = block
				if rule.filter is not None:
					if bool(m) != rule.filter: line = None
				if line is None: break
			if line is not None:
				for chan in chan_set: self.iface.send_msg(chan, self.chan_names[chan], line)
		return buff

	async def run(self):
		self.log.debug('Starting infinite tailer-loops for {} file(s)...', len(self.file_chans))
		await self.iface.lib.aio_loop(*(
			self.run_file_tailer(p, ft.partial(self.proc_file_updates, p, chan_set))
			for p, chan_set in self.file_chans.items() ))


# Any last assignment will be used as an entry point
blade_init = LogTailer
