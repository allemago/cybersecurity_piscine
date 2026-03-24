# Vaccine

A scanner for detecting and exploiting SQL injection vulnerabilities. Provide a URL, and it will identify vulnerable parameters, fingerprint the database engine, and extract its contents: tables, columns, and data and save it to an output file.

# Usage

```bash
# Install all dependencies
poetry install
```

---
## MySQL

### Vulnweb Acunetix (may be unavailable)
```bash
# form fields only
poetry run vaccine -o mysql_test.json "http://testphp.vulnweb.com/login.php"
```
```bash
# form fields + query parameters
poetry run vaccine -o mysql_test.json -X <method> "http://testphp.vulnweb.com/artists.php?artist=3"
```

### DVWA - Docker
```bash
# Pull image once
docker pull vulnerables/web-dvwa
```
```bash
# Run the container
docker run --rm -d --name dvwa vulnerables/web-dvwa
```
```bash
# Get IP address
docker inspect dvwa | grep IPAddress
```
#### DVWA CONFIG - 3 STEPS
##### 1 - init database "Create / Reset Database"
```
http://<IP>/setup.php
```

##### 2 - log in
To login you can use the following credentials:  
Username: admin  
Password: password  
```
http://<IP>/login.php
```

##### 3 - set level to low in DVWA Security
```
http://<IP>/security.php
```

```bash
# form fields only
poetry run vaccine -o mysql_test.json -C "PHPSESSID=<PHPSESSID_HERE>; security=low" "http://<IP>/vulnerabilities/sqli/"
```
```bash
# form fields + query parameters
poetry run vaccine -o mysql_test.json -X <method> -C "PHPSESSID=<PHPSESSID_HERE>; security=low" "http://<IP>/vulnerabilities/sqli/?id=1&Submit=Submit"
```

---
## SQLite
### app_sqlite - Flask
```bash
poetry run app_sqlite
```
```bash
# form fields only
poetry run vaccine -o sqlite_test.json "http://localhost:5000/"
```
```bash
# form fields + query parameters
poetry run vaccine -o sqlite_test.json -X GET "http://localhost:5000/search?q=test"

```
---

# References

### DVWA (Damn Vulnerable Web App):

<https://hub.docker.com/r/vulnerables/web-dvwa>
