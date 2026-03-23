# ft_onion

A Tor hidden service running a static web page and SSH server using Docker Compose with separate containers for each service.

## Requirements

- Docker
- Docker Compose

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Docker Network                           │
│                                                             │
│  ┌────────┐    ┌────────┐    ┌────────┐    ┌────────┐      │
│  │  nginx │    │  sshd  │    │  tor   │    │ client │      │
│  │  :80   │    │ :4242  │    │(hidden │    │  test  │      │
│  └───▲────┘    └───▲────┘    │service)│    └────────┘      │
│      │             │         └───┬────┘                     │
│      └─────────────┴─────────────┘                         │
│                    │                                        │
│             xxx.onion                                       │
└─────────────────────────────────────────────────────────────┘
                     │
                     ▼
              Tor Network (Internet)
```

Each service runs in its own container:
- **nginx**: Serves the static web page on port 80
- **sshd**: Provides SSH access on port 4242
- **tor**: Creates the hidden service and routes traffic
- **client**: Test container with Tor and torsocks

No ports are exposed to the host machine. All traffic goes through the Tor network.

## Build & Run

### 1. Start the services

The `ROOT_PASSWORD` environment variable is **required** for SSH access:

```bash
echo "ROOT_PASSWORD=password" > .env
docker compose up --build -d
```

### 2. Get the .onion address

```bash
docker compose exec tor cat /var/lib/tor/hidden_service/hostname
```

## Testing

### Start the test client

```bash
docker compose --profile test run --rm client
```

### Inside the client container

```bash
# Test the web page
torsocks curl http://ADDRESS.onion

# Test SSH connection
torsocks ssh -p 4242 root@ADDRESS.onion
```

## Verification: No Ports Exposed

```bash
docker compose ps
```

## Stop & Clean Up

```bash
# Stop services
docker compose down

# Stop and remove volumes (resets .onion address)
docker compose down -v
```

## Files Description

| File | Purpose |
|------|---------|
| `compose.yml` | Orchestrates all services with proper networking |
| `nginx/nginx.conf` | Configures nginx to serve static files on port 80 |
| `sshd/sshd_config` | Configures SSH to listen on port 4242 |
| `tor/torrc` | Configures Tor hidden service pointing to nginx and sshd containers |
| `nginx/index.html` | The static web page served by nginx |

## Persistent .onion Address

The `.onion` address is stored in a Docker volume (`tor_keys`).
