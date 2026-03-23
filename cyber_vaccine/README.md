# Vaccine - (in progress)

A scanner for detecting and exploiting SQL injection vulnerabilities. Provide a URL, and it will identify vulnerable parameters, fingerprint the database engine, and extract its contents: tables, columns, and data and save it to an output file.

# Usage

```bash
# Install all dependencies
poetry install
```


---
## MySQL

### Web (if it's working)
```bash
poetry run vaccine -o mysql_test.json -X POST http://testphp.vulnweb.com/login.php
# or
poetry run vaccine -o mysql_test.json -X GET http://testphp.vulnweb.com/artists.php?artist=3
```

### Docker
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
```bash
# DVWA config - 3 steps
1 - init database "Create / Reset Database":
http://<IP>/setup.php

2 - log in:
# To login you can use the following credentials:
# Username: admin
# Password: password
http://<IP>/login.php

3 - set level to low in DVWA Security
```
```bash
# Run the scanner
poetry run vaccine -o mysql_test.json -X GET http://<IP>/vulnerabilities/sqli/?id=1&Submit=Submit
```

---
## SQLite

### Docker
```bash
# Pull image once
docker pull bkimminich/juice-shop
```
```bash
# Run the container
docker run --rm -d --name juiceshop bkimminich/juice-shop
```
```bash
# Get IP address
docker inspect juiceshop | grep IPAddress
```
```bash
# Run the scanner
poetry run vaccine -o sqlite_test.json -X POST http://<IP>:3000/#/login
# or
poetry run vaccine -o sqlite_test.json -X GET http://<IP>/#/search?q=test
```
---

# References

### DVWA (Damn Vulnerable Web App):
```
https://hub.docker.com/r/vulnerables/web-dvwa
```

### OWASP Juice Shop
```
https://hub.docker.com/r/bkimminich/juice-shop
```
