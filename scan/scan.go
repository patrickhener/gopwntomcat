package scan

import (
	"fmt"
	"log"
	"net/http"
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

func worker(id int, scanJobs <-chan scanJob, result chan<- *result) {
	for scanJob := range scanJobs {
		ip := scanJob.ip
		port := scanJob.port
		ssl := scanJob.ssl
		targeturi := scanJob.targeturi
		go func() {
			res := scan(ip, port, ssl, targeturi)
			result <- res
		}()
	}
}

func scan(host string, port int, ssl bool, targetURI string) *result {
	var (
		resp   *http.Response
		err    error
		url    string
		res    *result
		client *http.Client
		req    *http.Request
	)

	res = new(result)
	if ssl {
		url = fmt.Sprintf("https://%s:%d%s", host, port, targetURI)
	} else {
		url = fmt.Sprintf("http://%s:%d%s", host, port, targetURI)
	}
	if resp, err = http.Head(url); err != nil {
		return res
	}

	log.Printf("Host %s responded to %s request", host, targetURI)

	if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("WWW-Authenticate") == "" {
		log.Printf("%s: Target does not appear to require Basic auth.", host)
		return res
	}

	log.Printf("Host %s requires authentication. Proceeding with password guessing...", host)
	client = new(http.Client)
	if req, err = http.NewRequest("GET", url, nil); err != nil {
		log.Println("Unable to build GET request")
		return res
	}

	for _, user := range utils.DefaultUsers {
		for _, pass := range utils.DefaultPasswords {
			req.SetBasicAuth(user, pass)
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
	}
	return res
}

// Start will start the scanning
func Start(rhostsFlag utils.Rhosts, port, threads int, ssl bool, targeturi string) {
	var ips []string
	var scanJobs []scanJob

	// Parse and fill up ips
	for _, rhost := range rhostsFlag {
		ips = append(ips, utils.ProcessIps(rhost)...)
	}

	for _, ip := range ips {
		scanJobs = append(scanJobs, scanJob{ip: ip, port: port, ssl: ssl, targeturi: targeturi})
	}

	log.Println("Started scan")

	numJobs := len(scanJobs)
	jobChannel := make(chan scanJob, numJobs)
	resultChannel := make(chan *result, numJobs)

	// Init workers
	for w := 1; w <= threads; w++ {
		go worker(w, jobChannel, resultChannel)
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
			fmt.Println(result.details)
		}
	}

	fmt.Println(strings.Repeat("-", 64))
	log.Println("Scan completed")
}
