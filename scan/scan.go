package scan

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/patrickhener/gopwntomcat/utils"
)

type scanJob struct {
	ip        string
	port      int
	ssl       bool
	targeturi string
}

type result struct {
	vulnerable bool
	details    string
}

func worker(id int, scanJobs <-chan scanJob, result chan<- *result, proxy string) {
	for scanJob := range scanJobs {
		ip := scanJob.ip
		port := scanJob.port
		ssl := scanJob.ssl
		targeturi := scanJob.targeturi
		go func() {
			res := scan(ip, port, ssl, targeturi, proxy)
			result <- res
		}()
	}
}

func scan(host string, port int, ssl bool, targetURI string, proxy string) *result {
	var (
		resp   *http.Response
		err    error
		uri    string
		res    *result
		client *http.Client
		req    *http.Request
	)

	client = &http.Client{}

	res = new(result)
	if ssl {
		uri = fmt.Sprintf("https://%s:%d%s", host, port, targetURI)
	} else {
		uri = fmt.Sprintf("http://%s:%d%s", host, port, targetURI)
	}

	if proxy != "" {
		prx, err := url.Parse(proxy)
		if err != nil {
			panic(err)
		}
		client.Transport = &http.Transport{
			Proxy: http.ProxyURL(prx),
		}
	}

	if resp, err = client.Head(uri); err != nil {
		return res
	}

	log.Printf("Host %s responded to %s request", host, targetURI)

	if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("WWW-Authenticate") == "" {
		log.Printf("%s: Target does not appear to require Basic auth.", host)
		return res
	}

	log.Printf("Host %s requires authentication. Proceeding with password guessing...", host)
	if req, err = http.NewRequest("GET", uri, nil); err != nil {
		log.Println("Unable to build GET request")
		return res
	}

	for _, creds := range utils.DefaultBasicAuthenticationList {
		hit, _ := base64.StdEncoding.DecodeString(creds)
		user := strings.Split(string(hit), ":")[0]
		pass := strings.Split(string(hit), ":")[1]
		req.Header.Set("Authorization", fmt.Sprintf("Basic %s", creds))
		if resp, err = client.Do(req); err != nil {
			log.Println("Unable to send GET request")
			continue
		}
		if resp.StatusCode == http.StatusOK {
			res.vulnerable = true
			res.details = fmt.Sprintf("Valid credentials found @%s - %s:%s", host, user, pass)
			return res
		}
	}
	return res
}

// Start will start the scanning
func Start(rhostsFlag utils.Rhosts, port, threads int, ssl bool, targeturi string, proxy string, file string) {
	var ips []string
	var scanJobs []scanJob

	// Switch between file or rhosts
	if file != "" {
		f, err := os.Open(file)
		if err != nil {
			panic("Error opening the file " + err.Error())
		}
		scanner := bufio.NewScanner(f)

		for scanner.Scan() {
			u, err := url.Parse(scanner.Text())
			if err != nil {
				fmt.Printf("Error when parsing %s - not added to scan\n", scanner.Text())
				continue
			}
			portInt, _ := strconv.Atoi(u.Port())
			if u.Scheme == "https" {
				job := scanJob{ip: u.Hostname(), port: portInt, ssl: true, targeturi: targeturi}
				scanJobs = append(scanJobs, job)
			} else {
				job := scanJob{ip: u.Hostname(), port: portInt, ssl: false, targeturi: targeturi}
				scanJobs = append(scanJobs, job)
			}
		}
	} else {
		// Parse and fill up ips
		for _, rhost := range rhostsFlag {
			ips = append(ips, utils.ProcessIps(rhost)...)
		}

		for _, ip := range ips {
			scanJobs = append(scanJobs, scanJob{ip: ip, port: port, ssl: ssl, targeturi: targeturi})
		}
	}

	log.Println("Started scan")

	numJobs := len(scanJobs)
	jobChannel := make(chan scanJob, numJobs)
	resultChannel := make(chan *result, numJobs)

	// Init workers
	for w := 1; w <= threads; w++ {
		go worker(w, jobChannel, resultChannel, proxy)
	}

	// Pipe jobs to job channel
	go func() {
		for j := 0; j < numJobs; j++ {
			jobChannel <- scanJobs[j]
		}
		close(jobChannel)
	}()

	fmt.Printf("\r")
	fmt.Println(strings.Repeat("-", 64))

	for a := 1; a <= numJobs; a++ {
		result := <-resultChannel
		if result.vulnerable {
			log.Println(result.details)
		}
	}

	fmt.Println(strings.Repeat("-", 64))
	log.Println("Scan completed")
}
