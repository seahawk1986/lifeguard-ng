lifeguard-ng
============

a replacement for vdr-addon-lifeguard, run it as a service (as root), call it via dbus from everywhere without need for root permissions

check-lifeguard
---------------

run check-lifeguard to ask lifeguard-ng wether a save shutdown is possible.

Example:
```
$ ./check-lifeguard
method return sender=:1.272 -> dest=:1.275 reply_serial=2
   boolean false
   string "SSH connection from ::ffff:192.168.1.132 active"
```
