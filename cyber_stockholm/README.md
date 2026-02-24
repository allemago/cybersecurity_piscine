# Stockholm

Educational ransomware simulation - Cybersecurity Piscine

## Requirements

- Docker

## Build
```bash
docker build -t stockholm .
```

## Run
```bash
docker run -it stockholm
```

## Usage
```bash
# Display help
./stockholm -h

# Display version
./stockholm -v

# Encrypt files in ~/infection
./stockholm

# Encrypt silently
./stockholm -s

# Decrypt files
./stockholm -r <key>

# Decrypt silently
./stockholm -r <key> -s
```

## Testing
```bash
# Create test files
cd /home/infection
echo "secret data" > document.doc
echo "important" > spreadsheet.xls
echo "photo" > image.jpg

# Encrypt
cd /app
./stockholm

# Check encrypted files
ls /home/infection
# document.doc.ft  spreadsheet.xls.ft  image.jpg.ft

# Decrypt
./stockholm -r "your_key_here"

# Verify
cat /home/infection/document.doc
# secret data
```
