package main

import (
	"bytes"
	"fmt"
	"net/netip"
	"os/exec"
	"regexp"
	"sort"
	"strings"
)

const (
	tableName = "pathviz"
	// exitStage is the name of the probe that sits after all classic stages of a hook.
	// A packet that reaches it has survived the whole hook.
	exitStage = "exit"
	// exitPriority is higher than every classic iptables/nftables priority
	// (srcnat is 100, SELinux last is 225, conntrack helpers are 300).
	exitPriority = 500
)

// ifaceName is what a Linux interface name may look like (at most 15 characters).
var ifaceName = regexp.MustCompile(`^[A-Za-z0-9_.@-]{1,15}$`)

// splitIface splits a filter entry such as "in:eth0" into the direction
// ("in", "out", or "" for both) and the interface name.
func splitIface(entry string) (dir, name string) {
	for _, d := range []string{"in", "out"} {
		if rest, ok := strings.CutPrefix(entry, d+":"); ok {
			return d, rest
		}
	}
	return "", entry
}

// needsCandidates tells whether the filter names an output device.
func (f Filter) needsCandidates() bool {
	for _, entry := range f.Ifaces {
		if dir, _ := splitIface(entry); dir != "in" {
			return true
		}
	}
	return false
}

// Keeps tells whether a finished journey satisfies the interface part of the
// filter. It weeds out the packets that the PREROUTING probes logged only
// because their output device was not known yet.
func (f Filter) Keeps(j *Journey) bool {
	if !f.needsCandidates() {
		return true
	}
	for _, entry := range f.Ifaces {
		dir, name := splitIface(entry)
		for _, h := range j.Hops {
			if (dir != "out" && h.In == name) || (dir != "in" && h.Out == name) {
				return true
			}
		}
	}
	return false
}

// rememberFor is how long the kernel remembers a matched packet. A packet crosses
// all hooks within microseconds, and a short time keeps look-alikes out.
const rememberFor = "500ms"

// packetKeys are the NAT-invariant identities of a packet, one set per protocol.
// The guard is needed where the key alone does not pin the packet kind down.
// tcpFlagsByte is the byte with the TCP flags (offset 13 of the TCP header),
// taken as a raw payload. It is the same field as "tcp flags", but a set keyed
// on "tcp flags" makes "nft list" abort when it prints the elements
// (nftables 1.0.9: Assertion `ilen > 0' failed in concat_expr_msort_value).
const tcpFlagsByte = "@th,104,8"

var packetKeys = []struct{ set, guard, key string }{
	{"tcp4", "", "ip id . tcp sequence . tcp ackseq . " + tcpFlagsByte},
	// A UDP payload shorter than 8 bytes cannot be loaded by the first key.
	{"udp4", "udp length >= 16 ", "ip id . udp length . @th,64,64"},
	{"udp4short", "udp length < 16 ", "ip id . udp length"},
	{"icmp4", "", "ip id . icmp type . icmp sequence"},
	{"tcp6", "", "ip6 flowlabel . tcp sequence . tcp ackseq . " + tcpFlagsByte},
	{"udp6", "udp length >= 16 ", "ip6 flowlabel . udp length . @th,64,64"},
	{"udp6short", "udp length < 16 ", "ip6 flowlabel . udp length"},
	{"icmp6", "", "ip6 flowlabel . icmpv6 type . icmpv6 sequence"},
}

// Stage is one classic table position inside a hook (e.g. "mangle" in PREROUTING).
type Stage struct {
	Name     string `json:"name"`
	Priority int    `json:"priority"`
}

// Hook is one netfilter hook with its stages in traversal order.
type Hook struct {
	Name   string  `json:"name"`
	Stages []Stage `json:"stages"`
}

// Hooks lists the hooks and the stages iptables users know, in traversal order.
// The priorities are the ones the kernel uses for the iptables tables.
var Hooks = []Hook{
	{"PREROUTING", []Stage{{"raw", -300}, {"mangle", -150}, {"nat", -100}}},
	{"INPUT", []Stage{{"mangle", -150}, {"filter", 0}, {"nat", 100}}},
	{"FORWARD", []Stage{{"mangle", -150}, {"filter", 0}}},
	{"OUTPUT", []Stage{{"raw", -300}, {"mangle", -150}, {"nat", -100}, {"filter", 0}}},
	{"POSTROUTING", []Stage{{"mangle", -150}, {"nat", 100}}},
}

// Filter selects the traffic to trace. Every field matches in either direction:
// an IP matches the source or the destination address, a port matches the source
// or the destination port, an interface matches the input or the output device.
type Filter struct {
	Proto string `json:"proto"` // any, tcp, udp, icmp
	// Ifaces are interface names. A bare name matches the input or the output
	// device, "in:eth0" only the input device, and "out:eth0" only the output
	// device. Mind that the input device is unknown in OUTPUT, and the output
	// device is unknown in PREROUTING and INPUT.
	Ifaces []string `json:"ifaces"`
	IPs    []string `json:"ips"` // addresses or CIDR prefixes
	Ports  []int    `json:"ports"`
}

// Normalize validates the filter and brings it to a canonical form.
// Only validated values ever reach the nft script.
func (f *Filter) Normalize() error {
	f.Proto = strings.ToLower(strings.TrimSpace(f.Proto))
	if f.Proto == "" {
		f.Proto = "any"
	}
	switch f.Proto {
	case "any", "tcp", "udp", "icmp":
	default:
		return fmt.Errorf("unknown protocol %q (use any, tcp, udp, or icmp)", f.Proto)
	}

	ifaces := make([]string, 0, len(f.Ifaces))
	seenIface := map[string]bool{}
	for _, entry := range f.Ifaces {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		_, name := splitIface(entry)
		if !ifaceName.MatchString(name) {
			return fmt.Errorf("bad interface %q (use eth0, in:eth0, or out:eth0)", entry)
		}
		if !seenIface[entry] {
			seenIface[entry] = true
			ifaces = append(ifaces, entry)
		}
	}
	sort.Strings(ifaces)
	f.Ifaces = ifaces

	ips := make([]string, 0, len(f.IPs))
	seen := map[string]bool{}
	for _, raw := range f.IPs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		var canon string
		if strings.Contains(raw, "/") {
			p, err := netip.ParsePrefix(raw)
			if err != nil {
				return fmt.Errorf("bad prefix %q", raw)
			}
			canon = p.Masked().String()
		} else {
			a, err := netip.ParseAddr(raw)
			if err != nil || a.Zone() != "" {
				return fmt.Errorf("bad IP address %q", raw)
			}
			canon = a.Unmap().String()
		}
		if !seen[canon] {
			seen[canon] = true
			ips = append(ips, canon)
		}
	}
	f.IPs = ips

	ports := make([]int, 0, len(f.Ports))
	seenPort := map[int]bool{}
	for _, p := range f.Ports {
		if p < 1 || p > 65535 {
			return fmt.Errorf("bad port %d", p)
		}
		if !seenPort[p] {
			seenPort[p] = true
			ports = append(ports, p)
		}
	}
	sort.Ints(ports)
	f.Ports = ports
	if len(f.Ports) > 0 && f.Proto == "icmp" {
		return fmt.Errorf("ICMP has no ports")
	}
	return nil
}

// matches returns the nft match expressions of the filter. A packet is traced
// when it satisfies at least one of them.
func (f Filter) matches() []string {
	var v4, v6 []string
	for _, ip := range f.IPs {
		if strings.Contains(ip, ":") {
			v6 = append(v6, ip)
		} else {
			v4 = append(v4, ip)
		}
	}
	set := func(items []string) string { return "{ " + strings.Join(items, ", ") + " }" }

	ifaceAlts := []string{""}
	if len(f.Ifaces) > 0 {
		var in, out []string
		for _, entry := range f.Ifaces {
			dir, name := splitIface(entry)
			if dir != "out" {
				in = append(in, `"`+name+`"`)
			}
			if dir != "in" {
				out = append(out, `"`+name+`"`)
			}
		}
		ifaceAlts = nil
		if len(in) > 0 {
			ifaceAlts = append(ifaceAlts, "meta iifname "+set(in))
		}
		if len(out) > 0 {
			ifaceAlts = append(ifaceAlts, "meta oifname "+set(out))
		}
	}

	ipAlts := []string{""}
	if len(f.IPs) > 0 {
		ipAlts = nil
		if len(v4) > 0 {
			ipAlts = append(ipAlts, "ip saddr "+set(v4), "ip daddr "+set(v4))
		}
		if len(v6) > 0 {
			ipAlts = append(ipAlts, "ip6 saddr "+set(v6), "ip6 daddr "+set(v6))
		}
	}

	proto := ""
	switch f.Proto {
	case "tcp", "udp":
		proto = "meta l4proto " + f.Proto
	case "icmp":
		proto = "meta l4proto { icmp, ipv6-icmp }"
	case "any":
		if len(f.Ports) > 0 {
			proto = "meta l4proto { tcp, udp }"
		}
	}

	portAlts := []string{""}
	if len(f.Ports) > 0 {
		ps := make([]string, len(f.Ports))
		for i, p := range f.Ports {
			ps[i] = fmt.Sprint(p)
		}
		portAlts = []string{"th sport " + set(ps), "th dport " + set(ps)}
	}

	var out []string
	for _, iface := range ifaceAlts {
		for _, ip := range ipAlts {
			for _, port := range portAlts {
				parts := []string{}
				for _, s := range []string{iface, ip, proto, port} {
					if s != "" {
						parts = append(parts, s)
					}
				}
				out = append(out, strings.Join(parts, " "))
			}
		}
	}
	return out
}

// Ruleset renders the nft script that installs the probes. The script replaces
// the whole table in a single transaction.
//
// Every probe is a base chain registered right before a classic stage (priority - 1),
// so it sees the packet as it enters the stage. The chains are of the filter type
// and never issue a verdict of their own: each rule logs the packet to the NFLOG
// group and returns.
//
// The first probe that matches a packet remembers the packet's identity in a set
// for a moment, and every later probe also logs the remembered packets. The
// identity consists of header fields that NAT does not rewrite, so a packet stays
// in view after DNAT or SNAT changes the addresses or ports the filter looks at.
// Nothing in the packet itself is touched.
func Ruleset(f Filter, group int, skipPorts []int) string {
	var b bytes.Buffer
	// The comments in the ruleset are for the reader of the help dialog and of
	// "pathviz rules". [static] marks what is the same for every filter, and
	// [filter] marks what is generated from the current filter.
	b.WriteString("# [static] Replace the table in one transaction: make sure it exists,\n")
	b.WriteString("#          delete it, and define it anew.\n")
	fmt.Fprintf(&b, "table inet %s\n", tableName)
	fmt.Fprintf(&b, "delete table inet %s\n\n", tableName)
	fmt.Fprintf(&b, "table inet %s {\n", tableName)

	fmt.Fprintf(&b, "\t# [static] Sets that hold the identity of a traced packet for %s. One set\n", rememberFor)
	b.WriteString("\t#          per kind of packet, keyed on fields that NAT does not rewrite.\n")
	for _, s := range packetKeys {
		fmt.Fprintf(&b, "\tset %s {\n\t\ttypeof %s\n\t\tflags dynamic,timeout\n\t\ttimeout %s\n\t}\n\n", s.set, s.key, rememberFor)
	}

	// "remember" stores the identity of a packet that matched the filter.
	// It is entered with goto, so its end returns to the probe chain.
	b.WriteString("\t# [static] Stores the identity of a packet that matched the filter. Its end\n")
	b.WriteString("\t#          returns to the probe chain, which logs the packet.\n")
	b.WriteString("\tchain remember {\n")
	for _, s := range packetKeys {
		fmt.Fprintf(&b, "\t\t%supdate @%s { %s }\n", s.guard, s.set, s.key)
	}
	b.WriteString("\t}\n\n")

	// "select" returns to the probe chain for the packets to trace and accepts
	// (ends the probe chain for) everything else.
	selectChain := func(name string, candidates []string) {
		if candidates == nil {
			b.WriteString("\t# [static] Decides for a probe whether to log a packet: a return goes back to the\n")
			b.WriteString("\t#          probe, which logs it, and an accept ends the probe without a record.\n")
			b.WriteString("\t#          Only the rules marked [filter] in it depend on the filter.\n")
		} else {
			b.WriteString("\t# [filter] The select chain of the PREROUTING probes. It exists because the\n")
			b.WriteString("\t#          filter names an output interface, which is not known in PREROUTING yet.\n")
		}
		fmt.Fprintf(&b, "\tchain %s {\n", name)
		if len(skipPorts) > 0 {
			b.WriteString("\t\t# [static] Never trace the web UI's own traffic.\n")
		}
		for _, p := range skipPorts {
			// The visualizer's own UI traffic must never be traced: every traced
			// packet produces more UI traffic.
			fmt.Fprintf(&b, "\t\ttcp sport %d accept\n", p)
			fmt.Fprintf(&b, "\t\ttcp dport %d accept\n", p)
		}
		if ms := f.matches(); len(ms) == 0 || ms[0] == "" {
			b.WriteString("\t\t# [filter] No filter is set, so every packet is remembered and logged.\n")
		} else {
			b.WriteString("\t\t# [filter] The packets that match the filter are remembered and logged.\n")
		}
		for _, m := range f.matches() {
			if m != "" {
				m += " "
			}
			fmt.Fprintf(&b, "\t\t%sgoto remember\n", m)
		}
		// A packet that matched the filter at an earlier probe stays in view even
		// after NAT rewrote the addresses or ports the filter looks at.
		b.WriteString("\t\t# [static] A packet that an earlier probe remembered is logged too, even\n")
		b.WriteString("\t\t#          if NAT rewrote the fields the filter looks at.\n")
		for _, s := range packetKeys {
			fmt.Fprintf(&b, "\t\t%s%s @%s return\n", s.guard, s.key, s.set)
		}
		if len(candidates) > 0 {
			b.WriteString("\t\t# [filter] Log every packet that matches the rest of the filter. PathViz\n")
			b.WriteString("\t\t#          keeps it only if it leaves through the right interface later.\n")
		}
		for _, m := range candidates {
			if m != "" {
				m += " "
			}
			fmt.Fprintf(&b, "\t\t%sreturn\n", m)
		}
		b.WriteString("\t\t# [static] Every other packet passes without a record.\n")
		b.WriteString("\t\taccept\n\t}\n\n")
	}
	selectChain("select", nil)
	// The output device is unknown in PREROUTING. When the filter asks for one,
	// the PREROUTING probes log every packet that satisfies the rest of the
	// filter, and pathviz keeps the packet only if it leaves through the right
	// device later (see Filter.Keeps).
	early := f.needsCandidates()
	if early {
		rest := f
		rest.Ifaces = nil
		selectChain("select_early", rest.matches())
	}

	chain := func(hook, stage string, prio int) {
		fmt.Fprintf(&b, "\tchain %s_%s {\n", strings.ToLower(hook), stage)
		fmt.Fprintf(&b, "\t\ttype filter hook %s priority %d; policy accept;\n", strings.ToLower(hook), prio)
		if early && hook == "PREROUTING" {
			fmt.Fprintf(&b, "\t\tjump select_early\n")
		} else {
			fmt.Fprintf(&b, "\t\tjump select\n")
		}
		fmt.Fprintf(&b, "\t\tlog group %d prefix \"%s/%s\"\n", group, stage, hook)
		fmt.Fprintf(&b, "\t}\n")
	}

	fmt.Fprintf(&b, "\t# [static] The probes. Every hook has one right before each of its stages\n")
	fmt.Fprintf(&b, "\t#          (the stage's priority minus 1) and one at its end (priority %d). A probe\n", exitPriority)
	fmt.Fprintf(&b, "\t#          asks the select chain and logs the chosen packets to NFLOG group %d.\n", group)
	for i, h := range Hooks {
		if i > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "\t# [static] The probes of %s.", h.Name)
		if early && h.Name == "PREROUTING" {
			b.WriteString(" [filter] They ask select_early.")
		}
		b.WriteString("\n")
		for _, s := range h.Stages {
			chain(h.Name, s.Name, s.Priority-1)
		}
		chain(h.Name, exitStage, exitPriority)
	}
	b.WriteString("}\n")
	return b.String()
}

func nft(stdin string, args ...string) error {
	cmd := exec.Command("nft", args...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// InstallProbes loads the ruleset, replacing a previous pathviz table if any.
func InstallProbes(ruleset string) error {
	err := nft(ruleset, "-f", "-")
	if err == nil {
		return nil
	}
	msg := err.Error()
	if strings.Contains(msg, "log group") && strings.Contains(msg, "No such file or directory") {
		return fmt.Errorf("%w\n\nThe kernel rejected nftables NFLOG rules (\"log group ...\"). PathViz needs nft logging support to trace packets.\n\nTry:\n  sudo modprobe nft_log\n  sudo modprobe nfnetlink_log\n\nIf those modules are unavailable (common on some WSL kernels), run PathViz on a Linux VM/host with nft logging support", err)
	}
	return err
}

// RemoveProbes deletes the pathviz table. A missing table is not an error.
func RemoveProbes() error {
	return nft(fmt.Sprintf("table inet %s\ndelete table inet %s\n", tableName, tableName), "-f", "-")
}
