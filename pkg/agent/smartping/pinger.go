package smartping

import (
	"github.com/go-ping/ping"
	"github.com/sirupsen/logrus"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"time"
)

// TryResolve tries to discover if the remote host is up using ICMP
func TryResolve(address string) bool {
	// Always return true for localhost
	magicNet := net.IPNet{
		IP:   net.IPv4(240, 0, 0, 0),
		Mask: []byte{0xf0, 0x00, 0x00, 0x00},
	}

	if ip := net.ParseIP(address).To4(); ip != nil && magicNet.Contains(ip) {
		logrus.Debug("MagicIP Ping detected, returning true")
		
		// Dynamically map the IP within the 127.x.x.x range
		mappedIP := fmt.Sprintf("127.%d.%d.%d", ip[1], ip[2], ip[3])
		logrus.Debugf("Mapped MagicIP to: %s", mappedIP)
		return true
	}
	methods := []func(string) (bool, error){
		RawPinger,
		CommandPinger,
	}
	for _, method := range methods {
		if result, err := method(address); err == nil {
			return result
		}
	}
	// Everything failed...
	return false
}

// RawPinger use ICMP sockets to discover if a host is up. This could require administrative permissions on some hosts
func RawPinger(target string) (bool, error) {
	pinger, err := ping.NewPinger(target)
	if err != nil {
		return false, err
	}
	pinger.Count = 1
	pinger.Timeout = 4 * time.Second // NMAP default timeout ?
	if runtime.GOOS == "windows" {
		pinger.SetPrivileged(true)
	}
	err = pinger.Run()
	if err != nil {
		return false, err
	}

	return pinger.PacketsRecv != 0, nil
}

// CommandPinger uses the internal ping command (dirty), but should not require privileges
func CommandPinger(target string) (bool, error) {
	countArg := "-c"
	waitArg := "-W"
	waitTime := "3"
	if runtime.GOOS == "windows" {
		countArg = "/n"
		waitArg = "/w"
		waitTime = "3000"
	}

	cmd := exec.Command("ping", countArg, "1", waitArg, waitTime, target)
	if err := cmd.Run(); err != nil {
		return false, err
	}
	return true, nil
}
