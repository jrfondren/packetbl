bin/packetbl::
	gprbuild

clean::
	gprclean

install::
	install -o root -m 700 bin/packetbl /usr/sbin
	[[ -f /etc/packetbl.conf ]] || install -o root -m 600 example.conf /etc/packetbl.conf
