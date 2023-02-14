package utils

import (
	"math/rand"
	"net"
	"strings"
	"time"
)

var (
	// DefaultBasicAuthenticationList are default login creds already base64 encoded
	DefaultBasicAuthenticationList = []string{
		"YWRtaW46", "YWRtaW46YWRtYW5hZ2Vy", "YWRtaW46YWRtaW4=", "QURNSU46QURNSU4=", "YWRtaW46YWRyb2xlMQ==", "YWRtaW46YWRyb290", "YWRtaW46YWRzM2NyZXQ=", "YWRtaW46YWR0b21jYXQ=", "YWRtaW46YWR2YWdyYW50", "YWRtaW46cGFzc3dvcmQ=", "YWRtaW46cGFzc3dvcmQx", "YWRtaW46UGFzc3dvcmQx", "YWRtaW46dG9tY2F0", "YWRtaW46dmFncmFudA==", "Ym90aDphZG1hbmFnZXI=", "Ym90aDphZG1pbg==", "Ym90aDphZHJvbGUx", "Ym90aDphZHJvb3Q=", "Ym90aDphZHMzY3JldA==", "Ym90aDphZHRvbWNhdA==", "Ym90aDphZHZhZ3JhbnQ=", "Ym90aDp0b21jYXQ=", "Y3hzZGs6a2RzeGM=", "ajJkZXBsb3llcjpqMmRlcGxveWVy", "bWFuYWdlcjphZG1hbmFnZXI=", "bWFuYWdlcjphZG1pbg==", "bWFuYWdlcjphZHJvbGUx", "bWFuYWdlcjphZHJvb3Q=", "bWFuYWdlcjphZHMzY3JldA==", "bWFuYWdlcjphZHRvbWNhdA==", "bWFuYWdlcjphZHZhZ3JhbnQ=", "bWFuYWdlcjptYW5hZ2Vy", "b3Z3ZWJ1c3I6T3ZXKmJ1c3Ix", "UUNDOlFMb2dpYzY2", "cm9sZTE6YWRtYW5hZ2Vy", "cm9sZTE6YWRtaW4=", "cm9sZTE6YWRyb2xlMQ==", "cm9sZTE6YWRyb290", "cm9sZTE6YWRzM2NyZXQ=", "cm9sZTE6YWR0b21jYXQ=", "cm9sZTE6YWR2YWdyYW50", "cm9sZTE6cm9sZTE=", "cm9sZTE6dG9tY2F0", "cm9sZTpjaGFuZ2V0aGlz", "cm9vdDphZG1hbmFnZXI=", "cm9vdDphZG1pbg==", "cm9vdDphZHJvbGUx", "cm9vdDphZHJvb3Q=", "cm9vdDphZHMzY3JldA==", "cm9vdDphZHRvbWNhdA==", "cm9vdDphZHZhZ3JhbnQ=", "cm9vdDpjaGFuZ2V0aGlz", "cm9vdDpvd2FzcGJ3YQ==", "cm9vdDpwYXNzd29yZA==", "cm9vdDpwYXNzd29yZDE=", "cm9vdDpQYXNzd29yZDE=", "cm9vdDpyMDB0", "cm9vdDpyb290", "cm9vdDp0b29y", "dG9tY2F0Og==", "dG9tY2F0OmFkbWFuYWdlcg==", "dG9tY2F0OmFkbWlu", "dG9tY2F0OmFkcm9sZTE=", "dG9tY2F0OmFkcm9vdA==", "dG9tY2F0OmFkczNjcmV0", "dG9tY2F0OmFkdG9tY2F0", "dG9tY2F0OmFkdmFncmFudA==", "dG9tY2F0OmNoYW5nZXRoaXM=", "dG9tY2F0OnBhc3N3b3Jk", "dG9tY2F0OnBhc3N3b3JkMQ==", "dG9tY2F0OnMzY3JldA==", "dG9tY2F0OnRvbWNhdA==", "eGFtcHA6eGFtcHA=", "c2VydmVyX2FkbWluOm93YXNwYndh", "YWRtaW46b3dhc3Bid2E=", "ZGVtbzpkZW1v"}
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
