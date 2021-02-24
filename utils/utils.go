package utils

import (
	"math/rand"
	"net"
	"strings"
	"time"
)

var (
	// DefaultUsers are the default tomcat users
	DefaultUsers = []string{"admin", "manager", "role1", "root", "tomcat", "both"}
	// DefaultPasswords are the default tomcat passwords
	DefaultPasswords = []string{"admin", "manager", "role1", "root", "tomcat", "s3cret", "vagrant"}
)

// Rhosts will represent a custom flag slice
type Rhosts []string

// Set is required to satisfy interface
func (r *Rhosts) Set(val string) error {
	*r = append(*r, val)
	return nil
}

// String is required to satisfy interface
func (r *Rhosts) String() string {
	return ""
}

// Increment will increment an IP address
func Increment(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// ProcessIps will transfer the CIDR range to single IPs
func ProcessIps(iprange string) []string {
	ip, ipNet, err := net.ParseCIDR(iprange)
	if err != nil {
		return []string{iprange}
	}

	var ips []string
	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); Increment(ip) {
		ips = append(ips, ip.String())
	}

	return ips
}

// CheckValidIP will check if an IP is valid
func CheckValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// RandTextAlphanumeric will return a random 32 long alphanumeric string
func RandTextAlphanumeric() string {
	rand.Seed(time.Now().UnixNano())
	chars := []rune("ABCDEFGHIJKLMNOPQRSTUVWXY" +
		"abcdefghijklmnopqrstuvwxyz" +
		"0123456789")
	length := 32
	var b strings.Builder
	for i := 0; i < length; i++ {
		b.WriteRune(chars[rand.Intn(len(chars))])
	}

	return b.String()
}
