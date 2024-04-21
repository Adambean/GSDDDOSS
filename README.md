# GSDDDOSS (GoldSource Denied Distributed Denial of Service Script)

GSDDDOSS is a simple Python script that monitors your GoldSrc/Svengine game server's UDP log output for the following attacks:

* Bad RCON attempts
* Split packets
* A2S abuse / Reflected DDoS

Any IP address associated with any of these attacks will be automagically blocked in your system's firewall.

(Blame H2 for the name 😛)

If you find a bug, or have improved on the script - feel free to make a pull request!

## Requirements

* Python 3.6 or greater.
* Administrator / super user privileges: This is necessary to block IP addresses with your system's firewall.

## Support

* Windows (tested)
* Linux (untested, but should work)

## Configuration

You can optionally define a configuration as follows as file "config.json". If it does not exist a default configuration will be created.

### `listener_addr`

Default: "127.0.0.1"

IP address for the log receiver to listen on. Specify "0.0.0.0" to listen on all IP addresses on the system.

If this tool is running on a different system to your game server you will need to configure relevant firewalls so that UDP traffic going in to the listener address/port is permitted.

**Always restrict this exclusively to the IP addresses of your game servers.** If you open this up to the world anyone can (fraudulently) trigger an IP address block without your consent.

### `listener_port`

Default: 8008

UDP port for log receiver to listen on.

(See firewall remark above.)

### `command_add_block`

Default: *(empty)*

Custom system command to run when blocking an IP address in your firewall.

* Include a placeholder "`{ip}`" for where the IP address should appear in your command.
* Leave empty/undefined to use the platform default:
  * On Windows this is: `netsh advfirewall firewall add rule name=\"Blocked IP\" dir=in interface=any action=block remoteip={}`
  * On Linux this is: `iptables -A INPUT -s {} -j DROP -m comment --comment "GSDDDOSS blocked"`
* [CSF+LFD (single)](https://configserver.com/configserver-security-and-firewall/) example: `csf -d {} "GSDDDOSS blocked"`
* [CSF+LFD (cluster)](https://configserver.com/configserver-security-and-firewall/) example: `csf -cd {} "GSDDDOSS blocked"`
* [IPSET](https://ipset.netfilter.org/) example: `add blocklist {} comment "GSDDDOSS blocked"` *(Replace "blocklist" with your intended set name).*
* [UFW](https://wiki.ubuntu.com/UncomplicatedFirewall?action=show&redirect=UbuntuFirewall) example: `ufw deny from {} to any`

### `windows_rule_ip_grouped`

Default: `True`

For Windows systems only: Group all blocked IP addresses into a single rule.

Turn this off if you find that you're exhausting the limitation of IP addresses in a single firewall rule. This is typically 1000, though increased to 10000 on Windows 11 and Windows Server 2022.

Bare in mind the alternative, when this is off, means that your firewall rule set will grow to many thousands. You can clear all of these in one go with this command:

```batch
netsh advfirewall firewall del rule name="GSDDDOSS blocked" dir=in
```

## Installation

Download & run the script. It will automatically start listening on UDP port **8008** or the port you configured above.

In your game server's "server.cfg" file (or alternative `servercfgfile`) add the line `logaddress_add 127.0.0.1 8008`. (Be sure to replace in the listener address/port you configured above.) Then apply this by either restarting the server, restarting/changing map, or execute the same line in the server console (either directly or via RCON).

To terminate the program either send CTRL+C (on Linux) or CTRL+BREAK (on Windows). **CTRL+C will not work on Windows currently.**

## Continuous running

Ideally you want to run the Python command in a loop or as a service in case it crashes or closes unexpectedly.

### Windows

To have this process running continuously in the background you could create a Batch script file of which loops itself after this tool closes.

Make a new ".bat" or ".cmd" file containing:

```batch
@echo off
title GSDDDOSS
:watch
python gsdddoss.py
goto watch
```

(This assumes `python` is available to the system's "PATH" environment variable.)

After that make a shortcut to the script file, and go to the shortcut properties. In the shortcut properties find the button labelled "Advanced" and tick off "Run as administrator". Then you just run the shortcut and press yes at the UAC.

You may prefer to use a service tool such as [FireDaemon Pro](https://www.firedaemon.com/firedaemon-pro).

### Linux

We'd suggest using `screen` or `tmux` on Linux.
