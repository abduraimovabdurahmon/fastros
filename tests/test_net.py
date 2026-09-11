"""Network commands: ip, ifconfig, route, arp, ping, netstat, ss, nc,
nslookup/host/dig, curl/wget, fw.

HTTP tests use a local `nc -l` responder so they don't depend on the internet
(the dev VM's user-net resolves DNS but has no outbound TCP)."""
import re
import time

import pytest


def test_ip_addr(g):
    out = g.ok("ip addr")
    assert "1: lo:" in out and "inet 127.0.0.1/8" in out
    assert re.search(r"2: eth0:.*mtu 1500", out)
    assert "link/ether 52:54:00:12:34:56" in out
    assert "inet 10.0.2.15/24 brd 10.0.2.255" in out


def test_ip_route(g):
    out = g.ok("ip route")
    assert "default via 10.0.2.2 dev eth0" in out
    assert "10.0.2.0/24 dev eth0 proto kernel scope link src 10.0.2.15" in out


def test_ip_link(g):
    out = g.ok("ip link")
    assert "1: lo:" in out and "2: eth0:" in out
    assert "link/ether 52:54:00:12:34:56" in out


def test_ifconfig(g):
    out = g.ok("ifconfig eth0")
    assert "inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255" in out
    assert "ether 52:54:00:12:34:56" in out


def test_route(g):
    out = g.ok("route -n")
    assert out.splitlines()[0] == "Kernel IP routing table"
    assert re.search(r"^0\.0\.0\.0 +10\.0\.2\.2 +0\.0\.0\.0 +UG ", out, re.M)
    assert re.search(r"^10\.0\.2\.0 +0\.0\.0\.0 +255\.255\.255\.0 +U ", out, re.M)


def test_ping_loopback(g):
    out = g.ok("ping -c 2 127.0.0.1", timeout=20)
    assert out.startswith("PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.")
    assert re.search(r"64 bytes from 127\.0\.0\.1: icmp_seq=\d+ ttl=\d+ time=[\d.]+ ms", out)
    assert "2 packets transmitted, 2 received, 0% packet loss" in out
    assert "rtt min/avg/max/mdev" in out


def test_ping_gateway(g):
    out = g.ok("ping -c 2 10.0.2.2", timeout=20)
    assert "2 packets transmitted, 2 received, 0% packet loss" in out


def test_ping_count_and_quiet(g):
    out = g.ok("ping -q -c 3 127.0.0.1", timeout=20)
    assert "bytes from" not in out
    assert "3 packets transmitted, 3 received" in out


def test_netstat_listening(g):
    out = g.ok("netstat -tln")
    assert out.splitlines()[0].startswith("Active Internet connections")
    assert "Proto Recv-Q Send-Q Local Address" in out.splitlines()[1]
    assert re.search(r"^tcp +0 +0 0\.0\.0\.0:22 +\*:\* +LISTEN", out, re.M)


def test_ss_listening(g):
    out = g.ok("ss -tln")
    assert "Local Address:Port" in out.splitlines()[0]
    assert re.search(r"^tcp +LISTEN.*0\.0\.0\.0:22", out, re.M)


def test_netstat_interfaces(g):
    out = g.ok("netstat -i")
    assert out.splitlines()[0] == "Kernel Interface table"
    assert any(l.startswith("eth0") for l in out.splitlines())
    assert any(l.startswith("lo") for l in out.splitlines())


def test_nc_transfer(g):
    out = g.ok("timeout 6 nc -l 9200 >/tmp/ncgot & sleep 0.5; "
               "echo 'ping over nc' | nc -w2 127.0.0.1 9200; sleep 0.5; cat /tmp/ncgot", timeout=20)
    assert "ping over nc" in out


def test_nc_scan(g):
    out = g.ok("nc -z 127.0.0.1 22", timeout=15)
    assert "Connection to 127.0.0.1 22 port [tcp/*] succeeded!" in out
    _, _, st = g.run("nc -z -w2 127.0.0.1 1", timeout=15)
    assert st == 1


def _serve(g, port, response, extra=""):
    """Run a one-shot HTTP responder on `port` and return the client command
    prefix that waits for it to be listening."""
    setup = f"printf '{response}' > /tmp/resp_{port}; timeout 8 nc -l {port} </tmp/resp_{port} >/dev/null & sleep 0.5; "
    return setup + extra


def test_curl_get(g):
    resp = r"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nContent-Type: text/plain\r\n\r\nhello world\n"
    out = g.ok(_serve(g, 9300, resp, "curl -sS http://127.0.0.1:9300/"), timeout=20)
    assert out == "hello world\n"


def test_curl_write_out_code(g):
    resp = r"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
    out = g.ok(_serve(g, 9301, resp, "curl -s -o /dev/null -w '%{http_code}\\n' http://127.0.0.1:9301/"), timeout=20)
    assert out.strip() == "404"


def test_curl_head(g):
    resp = r"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nServer: fastros\r\n\r\nabcde"
    out = g.ok(_serve(g, 9302, resp, "curl -sSI http://127.0.0.1:9302/"), timeout=20)
    assert out.startswith("HTTP/1.1 200 OK")
    assert "Server: fastros" in out
    assert "abcde" not in out  # HEAD: headers only


def test_curl_output_file(g):
    resp = r"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nsaved!!"
    out = g.ok(_serve(g, 9303, resp, "curl -s -o /tmp/curlout http://127.0.0.1:9303/; cat /tmp/curlout"), timeout=20)
    assert out == "saved!!"


def test_curl_chunked(g):
    resp = r"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
    out = g.ok(_serve(g, 9304, resp, "curl -sS http://127.0.0.1:9304/"), timeout=20)
    assert out == "hello world"


def test_curl_tls_unsupported(g):
    _, err, st = g.run("curl -sS https://example.com", timeout=20)
    assert st == 60 and "TLS is not supported" in err


def test_wget_download(g):
    resp = r"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\ndownload!"
    out = g.ok(_serve(g, 9305, resp, "wget -q -O /tmp/wgot http://127.0.0.1:9305/; cat /tmp/wgot"), timeout=20)
    assert out == "download!"


def test_nslookup_ip(g):
    out = g.ok("nslookup 8.8.8.8")
    assert "8.8.8.8.in-addr.arpa" in out
    assert "Server:" in out


def test_dns_resolve(g):
    # DNS (UDP) works in the dev VM even though outbound TCP does not.
    out, _, st = g.run("host example.com", timeout=20)
    if st == 0:
        assert "has address" in out
    else:
        pytest.skip("DNS unavailable in this environment")


def test_fw_status(g):
    out = g.ok("fw status")
    assert "Firewall: enabled" in out
    assert "Default policy: in drop / out accept" in out
    assert re.search(r"^0 +in +accept tcp +22 ", out, re.M)  # ssh rule
    assert "ping (rate limited)" in out


def test_fw_allow_deny(g):
    assert "opened tcp port 8443" in g.ok("fw allow tcp 8443")
    assert re.search(r"accept tcp +8443", g.ok("fw status"))
    assert "closed tcp port 8443" in g.ok("fw deny tcp 8443")
    assert not re.search(r"accept tcp +8443", g.ok("fw status"))


def test_fw_ban_unban(g):
    g.ok("fw ban 203.0.113.5 60")
    assert "203.0.113.5" in g.ok("fw bans")
    assert "unbanned 203.0.113.5" in g.ok("fw unban 203.0.113.5")


def test_fw_denied_to_unprivileged(g):
    # A normal user cannot change the firewall.
    g.run("userdel -r fwuser; useradd -m fwuser; echo 'fwuser:Pass-Word12' | chpasswd")
    from conftest import connect, Guest
    u = Guest(connect("fwuser", "Pass-Word12"))
    _, err, st = u.run("fw allow tcp 9999")
    assert st != 0 and "not permitted" in err
    g.run("userdel -r fwuser")
