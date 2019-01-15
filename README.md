# packetbl
- User space daemon that filters packets against realtime blacklists
- you can add a rule to the firewall to direct packets towards this daemon, which'll accept or reject the packet based on the result of a DNS request.  For example, an IP from 1.2.3.4 will be rejected if a DNS A record resolves for 4.3.2.1.some-realtime-blacklist
- inspired by / created with reference to https://github.com/zevenet/packetbl
- an init script isn't yet provided

## build
```
gprbuild
```

## read documentation
```
man ./packetbl.mdoc
```

## installation
```
make install
# modify /etc/packetbl.conf
```
or
```
copy bin/packetbl where desired.
create an /etc/packetbl.conf from example.conf
```

## quick usage
```
echo blacklistbl some-realtime-blacklist > my.conf
sudo iptables -I INPUT -p tcp -m tcp --dport 8080 -j NFQUEUE --queue-num 0
sudo bin/packetbl -f my.conf
# wait for packets to hit port 8080
```

## logging
- except for start-up errors (to stderr), all logging is via syslog(3), levels LOG\_ERR or LOG\_NOTICE
- you can watch logs by tailing /var/log/messages or (under systemd) by watching `journalctl -f`
- example log entry:
```
Jan 15 11:49:33 example.com packetbl[794]: cache-accepting packet: 127.0.0.1
```
