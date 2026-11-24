package main

import (
	"encoding/binary"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

// tcpPacket builds an IPv4 TCP packet with the given addresses, ports, and IP ID.
func tcpPacket(src, dst [4]byte, sport, dport, id uint16, ttl uint8) []byte {
	b := make([]byte, 40)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], 40)
	binary.BigEndian.PutUint16(b[4:], id)
	b[6] = 0x40 // DF
	b[8] = ttl
	b[9] = 6
	copy(b[12:], src[:])
	copy(b[16:], dst[:])
	binary.BigEndian.PutUint16(b[20:], sport)
	binary.BigEndian.PutUint16(b[22:], dport)
	binary.BigEndian.PutUint32(b[24:], 1000)
	b[32] = 0x50
	b[33] = 0x02 // SYN
	binary.BigEndian.PutUint16(b[34:], 64240)
	return b
}

func mustParse(t *testing.T, b []byte) Packet {
	t.Helper()
	p, err := ParsePacket(b)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParseTCP(t *testing.T) {
	p := mustParse(t, tcpPacket([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 40000, 8080, 7, 64))
	if p.Proto != "tcp" || p.SrcString() != "10.0.0.1:40000" || p.DstString() != "10.0.0.2:8080" {
		t.Fatalf("unexpected packet: %+v", p)
	}
	if p.Info != "SYN" || p.Detail != "seq=1000" {
		t.Fatalf("unexpected info: %q", p.Info)
	}
}

func TestFingerprintSurvivesNATAndForwarding(t *testing.T) {
	orig := mustParse(t, tcpPacket([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 40000, 8080, 7, 64))
	natted := mustParse(t, tcpPacket([4]byte{192, 168, 0, 9}, [4]byte{172, 17, 0, 2}, 1024, 80, 7, 63))
	if orig.fingerprint != natted.fingerprint {
		t.Fatal("NAT and a TTL decrement must not change the fingerprint")
	}
	other := mustParse(t, tcpPacket([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 40000, 8080, 8, 64))
	if orig.fingerprint == other.fingerprint {
		t.Fatal("packets with different IP IDs must have different fingerprints")
	}
}

func TestParseTruncated(t *testing.T) {
	if _, err := ParsePacket([]byte{0x45, 0}); err == nil {
		t.Fatal("expected an error for a truncated header")
	}
	// A packet cut in the middle of the TCP header still yields the addresses.
	p := mustParse(t, tcpPacket([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 1, 2, 7, 64)[:30])
	if p.Src.String() != "10.0.0.1" {
		t.Fatalf("unexpected packet: %+v", p)
	}
}

func collect(events []Event) []*Journey {
	var out []*Journey
	tr := NewTracker(func(j *Journey) { out = append(out, j) })
	var last time.Time
	for _, ev := range events {
		tr.Add(ev)
		last = ev.Time
	}
	tr.Flush(last.Add(time.Second))
	return out
}

func events(t *testing.T, start time.Time, pkt []byte, stages ...string) []Event {
	t.Helper()
	var out []Event
	for i, s := range stages {
		stage, hook, _ := strings.Cut(s, "/")
		out = append(out, Event{Time: start.Add(time.Duration(i) * time.Microsecond), Hook: hook, Stage: stage, Packet: mustParse(t, pkt)})
	}
	return out
}

func TestTrackerVerdicts(t *testing.T) {
	now := time.Now()
	pkt := tcpPacket([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 40000, 8080, 7, 64)

	in := []string{"raw/PREROUTING", "mangle/PREROUTING", "nat/PREROUTING", "exit/PREROUTING", "mangle/INPUT", "filter/INPUT", "nat/INPUT", "exit/INPUT"}
	js := collect(events(t, now, pkt, in...))
	if len(js) != 1 || js[0].Verdict != VerdictDelivered || js[0].Partial {
		t.Fatalf("delivered: %+v", js)
	}
	if got := strings.Join(js[0].Path, " "); got != "PREROUTING INPUT" {
		t.Fatalf("path: %q", got)
	}

	js = collect(events(t, now, pkt, in[:6]...))
	if js[0].Verdict != VerdictStopped || js[0].StoppedHook != "INPUT" || js[0].StoppedStage != "filter" {
		t.Fatalf("dropped in filter/INPUT: %+v", js[0])
	}

	js = collect(events(t, now, pkt, in[:4]...))
	if js[0].Verdict != VerdictStopped || js[0].StoppedStage != "routing" {
		t.Fatalf("lost after PREROUTING: %+v", js[0])
	}

	js = collect(events(t, now, pkt, "exit/PREROUTING", "mangle/INPUT", "filter/INPUT", "nat/INPUT", "exit/INPUT"))
	if js[0].Verdict != VerdictDelivered || !js[0].Partial {
		t.Fatalf("partial: %+v", js[0])
	}
}

func TestTrackerRewriteAndRepeat(t *testing.T) {
	now := time.Now()
	before := tcpPacket([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 40000, 8080, 7, 64)
	after := tcpPacket([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 40000, 80, 7, 64)
	evs := events(t, now, before, "raw/PREROUTING", "mangle/PREROUTING", "nat/PREROUTING")
	evs = append(evs, events(t, now.Add(10*time.Microsecond), after, "exit/PREROUTING", "mangle/INPUT", "filter/INPUT", "nat/INPUT", "exit/INPUT")...)
	js := collect(evs)
	if len(js) != 1 {
		t.Fatalf("a rewritten packet must stay one journey, got %d", len(js))
	}
	if got := js[0].Hops[2].Rewrote; got != "destination 10.0.0.2:8080 to 10.0.0.2:80" {
		t.Fatalf("rewrote: %q", got)
	}

	// The same stage seen twice means two packets that look the same.
	evs = events(t, now, before, "raw/OUTPUT", "raw/OUTPUT")
	if js := collect(evs); len(js) != 2 {
		t.Fatalf("expected 2 journeys, got %d", len(js))
	}
}

func TestSockets(t *testing.T) {
	out := `udp   UNCONN 0      0         127.0.0.53%lo:53         0.0.0.0:*     users:(("systemd-resolve",pid=335,fd=13))
udp   UNCONN 0      0                     *:8080              *:*     users:(("pathviz",pid=900,fd=4))
tcp   LISTEN 0      4096                  *:8080              *:*     users:(("pathviz",pid=900,fd=3))
tcp   LISTEN 0      128                [::]:22             [::]:*     users:(("sshd",pid=771,fd=4))
tcp   LISTEN 0      128             0.0.0.0:22          0.0.0.0:*     users:(("sshd",pid=771,fd=3))
tcp   ESTAB  0      0           172.16.0.20:8080    172.16.0.10:57308 users:(("pathviz",pid=900,fd=7))
tcp   ESTAB  0      0           172.16.0.20:40000   172.16.0.10:9000  users:(("curl",pid=1200,fd=5))
tcp   LISTEN 0      4096                  *:7070              *:*     users:(("pathviz",pid=800,fd=6))
tcp   LISTEN 0      5             127.0.0.1:631         0.0.0.0:*
`
	tbl := NewSocketTable([]int{7070})
	tbl.socks = parseSS(out)
	tbl.last = time.Now()
	if len(tbl.socks) != 8 {
		t.Fatalf("expected 8 sockets with a process, got %d", len(tbl.socks))
	}
	ap := netip.MustParseAddrPort
	if o := tbl.Owner("tcp", ap("172.16.0.20:8080"), ap("172.16.0.10:1")); o == nil || o.PID != 900 {
		t.Fatalf("listening socket owner: %+v", o)
	}
	if o := tbl.Owner("tcp", ap("172.16.0.20:40000"), ap("172.16.0.10:9000")); o == nil || o.Name != "curl" {
		t.Fatalf("connected socket owner: %+v", o)
	}
	if o := tbl.Owner("udp", ap("127.0.0.53:53"), ap("127.0.0.1:5000")); o == nil || o.PID != 335 {
		t.Fatalf("bound address owner: %+v", o)
	}
	if o := tbl.Owner("udp", ap("172.16.0.20:53"), ap("127.0.0.1:5000")); o != nil {
		t.Fatalf("a socket bound to another address must not match: %+v", o)
	}
	st := tbl.Snapshot()
	var names []string
	for _, p := range st.Procs {
		names = append(names, fmt.Sprintf("%s/%d/%d", p.Name, p.PID, len(p.Sockets)))
	}
	if got := strings.Join(names, " "); got != "sshd/771/1 systemd-resolve/335/1 pathviz/900/2" {
		t.Fatalf("processes: %q", got)
	}
}

func TestFilter(t *testing.T) {
	f := Filter{Proto: "TCP", IPs: []string{" 10.0.0.1 ", "10.0.0.1", "fd00::/8"}, Ports: []int{8080, 80, 80}}
	if err := f.Normalize(); err != nil {
		t.Fatal(err)
	}
	if len(f.IPs) != 2 || len(f.Ports) != 2 || f.Ports[0] != 80 {
		t.Fatalf("normalized: %+v", f)
	}
	if got := len(f.matches()); got != 8 {
		t.Fatalf("expected 8 match alternatives, got %d", got)
	}
	for _, bad := range []Filter{
		{Proto: "sctp"},
		{IPs: []string{"10.0.0.1; drop"}},
		{Ifaces: []string{`eth0" drop`}},
		{Ifaces: []string{"averyveryverylongname"}},
		{Ifaces: []string{"in:"}},
		{IPs: []string{"10.0.0.0/33"}},
		{Ports: []int{0}},
		{Proto: "icmp", Ports: []int{80}},
	} {
		if err := bad.Normalize(); err == nil {
			t.Fatalf("filter %+v must be rejected", bad)
		}
	}
	withIface := Filter{Proto: "tcp", Ifaces: []string{"eth0"}, Ports: []int{80}}
	if err := withIface.Normalize(); err != nil {
		t.Fatal(err)
	}
	if m := withIface.matches(); len(m) != 4 || m[0] != `meta iifname { "eth0" } meta l4proto tcp th sport { 80 }` {
		t.Fatalf("interface matches: %q", m)
	}
	directed := Filter{Ifaces: []string{"in:eth0", "out:veth-app", "lo"}}
	if err := directed.Normalize(); err != nil {
		t.Fatal(err)
	}
	if m := directed.matches(); len(m) != 2 || m[0] != `meta iifname { "eth0", "lo" }` || m[1] != `meta oifname { "lo", "veth-app" }` {
		t.Fatalf("directed interface matches: %q", m)
	}
	out := Filter{Proto: "tcp", Ifaces: []string{"out:veth-app"}}
	rsOut := Ruleset(out, 77, nil)
	if !strings.Contains(rsOut, "chain select_early") || !strings.Contains(rsOut, "meta l4proto tcp return") ||
		strings.Count(rsOut, "jump select_early") != 4 {
		t.Fatalf("an output device filter needs early candidates:\n%s", rsOut)
	}
	if strings.Contains(Ruleset(Filter{Ifaces: []string{"in:eth0"}}, 77, nil), "select_early") {
		t.Fatal("an input device filter needs no early candidates")
	}
	forwarded := &Journey{Hops: []Hop{{Hook: "PREROUTING", In: "eth0"}, {Hook: "FORWARD", In: "eth0", Out: "veth-app"}}}
	local := &Journey{Hops: []Hop{{Hook: "PREROUTING", In: "eth0"}, {Hook: "INPUT", In: "eth0"}}}
	if !out.Keeps(forwarded) || out.Keeps(local) {
		t.Fatal("only the journey that leaves through veth-app must be kept")
	}
	rs := Ruleset(Filter{Proto: "any"}, 77, []int{7070})
	if !strings.Contains(rs, "log group 77 prefix \"raw/PREROUTING\"") ||
		!strings.Contains(rs, "tcp dport 7070 accept") {
		t.Fatalf("unexpected ruleset:\n%s", rs)
	}
}

func TestInstallProbesExplainsMissingNftLogSupport(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to execute nft")
	}
	err := InstallProbes(Ruleset(Filter{Proto: "any"}, 77, nil))
	if err == nil {
		_ = RemoveProbes()
		t.Skip("kernel supports nft log group rules")
	}
	msg := err.Error()
	if strings.Contains(msg, "log group") && strings.Contains(msg, "No such file or directory") {
		if !strings.Contains(msg, "modprobe nft_log") || !strings.Contains(msg, "modprobe nfnetlink_log") {
			t.Fatalf("missing remediation in error: %s", msg)
		}
	}
}

func TestToken(t *testing.T) {
	app := &App{token: "secret", packetView: true, subs: map[chan []byte]bool{}}
	h := app.Handler()
	get := func(path, bearer string) int {
		r := httptest.NewRequest("GET", path, nil)
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	for _, c := range []struct {
		path, bearer string
		want         int
	}{
		{"/", "", 200},
		{"/app.js", "", 200},
		{"/api/session", "", 401},
		{"/api/session", "wrong", 401},
		{"/api/session?token=wrong", "", 401},
		{"/api/session", "secret", 204},
		{"/api/session?token=secret", "", 204},
		{"/api/ruleset", "", 401},
		{"/api/packet?id=1", "", 401},
		{"/api/packet?id=1", "secret", 404},
		{"/api/events", "", 401},
		{"/api/nothing", "", 401},
	} {
		if got := get(c.path, c.bearer); got != c.want {
			t.Errorf("GET %s (bearer %q) = %d, want %d", c.path, c.bearer, got, c.want)
		}
	}
	r := httptest.NewRequest("POST", "/api/clear", strings.NewReader("{}"))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Errorf("POST /api/clear without the token = %d, want 401", w.Code)
	}

	// No cookies: a browser would send them to every port of the host.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/?token=secret", nil))
	if c := w.Result().Cookies(); len(c) != 0 {
		t.Errorf("the page must not set cookies: %v", c)
	}
	r = httptest.NewRequest("GET", "/api/session", nil)
	r.AddCookie(&http.Cookie{Name: "pathviz_token_7070", Value: "secret"})
	r.AddCookie(&http.Cookie{Name: "token", Value: "secret"})
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Errorf("GET /api/session with the token in a cookie = %d, want 401", w.Code)
	}

	// --dangerously-skip-token: no token, no check.
	app.token = ""
	if got := get("/api/session", ""); got != 204 {
		t.Errorf("GET /api/session without a token check = %d, want 204", got)
	}

	a, _ := newToken()
	b, _ := newToken()
	if len(a) != 32 || a == b {
		t.Errorf("bad tokens: %q, %q", a, b)
	}

	const own, other = "0123456789abcdef", "fedcba9876543210"
	for _, c := range []struct {
		flag, env string
		skip      bool
		want      string // "random", "error", or the token
	}{
		{"", "", false, "random"},
		{"", "", true, ""},
		{own, "", false, own},
		{"", own, false, own},
		{own, other, false, own},
		{"short", "", false, "error"},
		{"0123456789 abcdef", "", false, "error"},
		{own, "", true, "error"},
		{"", own, true, "error"},
	} {
		got, isOwn, err := pickToken(c.flag, c.env, c.skip)
		switch c.want {
		case "error":
			if err == nil {
				t.Errorf("pickToken(%q, %q, %v) must fail", c.flag, c.env, c.skip)
			}
		case "random":
			if err != nil || len(got) != 32 || isOwn {
				t.Errorf("pickToken(%q, %q, %v) = %q, %v, %v", c.flag, c.env, c.skip, got, isOwn, err)
			}
		default:
			if err != nil || got != c.want || isOwn != (c.want != "") {
				t.Errorf("pickToken(%q, %q, %v) = %q, %v, %v", c.flag, c.env, c.skip, got, isOwn, err)
			}
		}
	}
}

func TestTokenFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string, mode os.FileMode) string {
		path := dir + "/" + name
		if err := os.WriteFile(path, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	if got, err := readTokenFile(write("ok", "  0123456789abcdef\n", 0o600)); err != nil || got != "0123456789abcdef" {
		t.Errorf("readTokenFile = %q, %v", got, err)
	}
	if _, err := readTokenFile(write("open", "0123456789abcdef", 0o644)); err == nil {
		t.Error("a token file that others can read must be refused")
	}
	if _, err := readTokenFile(write("empty", "\n", 0o600)); err == nil {
		t.Error("an empty token file must be refused")
	}
	if _, err := readTokenFile(dir + "/missing"); err == nil {
		t.Error("a missing token file must be refused")
	}
}
