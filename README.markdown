# Session Management Prototypes for Security and Performance Testing

This repository contains two Node.js Express applications implementing session-based (`server-session.js`) and JWT-based (`server-jwt.js`) authentication for a Master's thesis on *Comparative Analysis of Session Management Techniques*. The prototypes use Redis for user storage, bcrypt for password hashing, and Prometheus for performance metrics, enabling security (OWASP ZAP, Burp Suite, Postman) and performance (JMeter) testing on a localhost environment.

## Prerequisites

- **Operating System**: Linux, macOS, or Windows (with WSL recommended for Windows).
- **Hardware**: ≥8 GB RAM (16 GB recommended for ZAP and JMeter).
- **Software**:
  - **Node.js**: Version 18.x or higher (`node --version` to check).
  - **Redis**: Version 6.x or higher (`redis-server --version` to check).
  - **curl**: For testing API endpoints (`curl --version` to check).
  - **jq**: For parsing JSON responses (`jq --version` to check).
- **Tools for Testing** (optional, for thesis experiments):
  - OWASP ZAP 2.16.1: For security scans.
  - Burp Suite Community Edition: For packet capture and tampering tests.
  - Postman: For API testing.
  - JMeter: For performance testing.
  - Prometheus/Grafana: For monitoring metrics.

## Setup Instructions

1. **Clone the Repository**:
   ```bash
   git clone <repository-url>
   cd <repository-name>
   ```

2. **Install Node.js Dependencies**:
   - For both `server-session` and `server-jwt` folders:
     ```bash
     cd server-session
     npm install express redis@4.6.5 bcrypt express-session connect-redis prom-client
     cd ../server-jwt
     npm install express redis@4.6.5 bcrypt jsonwebtoken prom-client
     ```

3. **Install and Start Redis**:
   - Install Redis:
     - Ubuntu: `sudo apt update && sudo apt install redis-server`.
     - macOS: `brew install redis`.
     - Windows (WSL): `sudo apt install redis-server`.
   - Start Redis:
     ```bash
     redis-server
     ```
   - Verify: `redis-cli ping` (should return `PONG`).

## Running the Servers

1. **Session-Based Server (`server-session.js`)**:
   - Navigate to the session server directory:
     ```bash
     cd server-session
     ```
   - Run the server:
     ```bash
     node server-session.js
     ```
   - Server runs on `http://localhost:3000`.
   - Logs: `Server running at http://localhost:3000`.

2. **JWT-Based Server (`server-jwt.js`)**:
   - Navigate to the JWT server directory:
     ```bash
     cd server-jwt
     ```
   - Run the server:
     ```bash
     node server-jwt.js
     ```
   - Server runs on `http://localhost:3001`.
   - Logs: `JWT Server running at http://localhost:3001`.

## Testing the APIs

Use `curl`, Postman, or a browser to test the endpoints. Below are example `curl` commands for both servers.

### Session-Based Server (`http://localhost:3000`)

1. **Register**:
   ```bash
   curl -X POST http://localhost:3000/register \
     -H "Content-Type: application/json" \
     -d '{"username":"cybermacs-session","password":"cybermacs-session"}'
   ```
   - Expected response: `{"message":"User cybermacs-session registered successfully","userId":<id>}` (status `201`).

2. **Login (Capture `connect.sid`)**:
   ```bash
   curl -X POST http://localhost:3000/login \
     -H "Content-Type: application/json" \
     -d '{"username":"cybermacs-session","password":"cybermacs-session"}' \
     -c session-cookies.txt
   ```
   - Saves `connect.sid` cookie to `session-cookies.txt`.

3. **Extract `connect.sid`**:
   ```bash
   SID=$(grep connect.sid session-cookies.txt | awk '{print $7}')
   echo $SID
   ```

4. **Access Protected Endpoint**:
   ```bash
   curl http://localhost:3000/protected -b "connect.sid=$SID"
   ```
   - Expected response: `{"message":"Authenticated","user":{"username":"cybermacs-session","id":<id>}}` (status `200`).

5. **Logout**:
   ```bash
   curl -X POST http://localhost:3000/logout -b "connect.sid=$SID"
   ```
   - Expected response: `{"message":"Logout successful"}` (status `200`).

### JWT-Based Server (`http://localhost:3001`)

1. **Register**:
   ```bash
   curl -X POST http://localhost:3001/register \
     -H "Content-Type: application/json" \
     -d '{"username":"cybermacs-jwt","password":"cybermacs-jwt"}'
   ```
   - Expected response: `{"message":"User cybermacs-jwt registered successfully","userId":<id>}` (status `201`).

2. **Login (Capture JWT Token)**:
   ```bash
   curl -X POST http://localhost:3001/login \
     -H "Content-Type: application/json" \
     -d '{"username":"cybermacs-jwt","password":"cybermacs-jwt"}' \
     -o jwt-token.json
   ```
   - Saves token to `jwt-token.json`.

3. **Extract JWT Token**:
   ```bash
   TOKEN=$(jq -r '.token' jwt-token.json)
   echo $TOKEN
   ```

4. **Access Protected Endpoint**:
   ```bash
   curl http://localhost:3001/protected \
     -H "Authorization: Bearer $TOKEN"
   ```
   - Expected response: `{"message":"Authenticated","user":{"username":"cybermacs-jwt","id":<id>,"iat":<time>,"exp":<time>}}` (status `200`).

5. **Logout**:
   ```bash
   curl -X POST http://localhost:3001/logout \
     -H "Authorization: Bearer $TOKEN"
   ```
   - Expected response: `{"message":"Logout successful (discard token client-side)"}` (status `200`).

## Security Testing with OWASP ZAP

1. **Start ZAP**:
   ```bash
   cd ~/zaproxy
   ./zap.sh
   ```
   - Proxy: `127.0.0.1:8080`.


2. **Capture Traffic**:
   - Run `curl` commands through ZAP’s proxy (add `--proxy http://127.0.0.1:8080` to each command above).
   - Example for session server:
     ```bash
     curl --proxy http://127.0.0.1:8080 -X POST http://localhost:3000/register \
       -H "Content-Type: application/json" \
       -d '{"username":"cybermacs-session","password":"cybermacs-session"}'
     ```

3. **Spider and Scan**:
   - Create context (`SessionServer` or `JWTServer`).
   - Set scope: `http://localhost:3000/.*` or `http://localhost:3001/.*`.
   - Configure authentication:
     - Session: Cookie-based, use `connect.sid` from `session-cookies.txt`.
     - JWT: Header-based, use `Authorization: Bearer <token>` from `jwt-token.json`.
   - Run spider and active scans, save reports to `ZAP Results`.

## Performance Testing with JMeter

1. **Install JMeter**:
   - Download from [apache.org](https://jmeter.apache.org/download_jmeter.cgi).
   - Run: `cd ~/jmeter/bin && ./jmeter`.

2. **Run Tests**:
   - Use JMeter test plans (e.g., `user-registration.jmx`, `session-test.jmx`, `jwt-test.jmx`).
   - Save results: `ZAP Results/jmeter-session.csv`, `ZAP Results/jmeter-jwt.csv`.

## Monitoring with Prometheus/Grafana

1. **Access Metrics**:
   - Session server: `curl http://localhost:3000/metrics`.
   - JWT server: `curl http://localhost:3001/metrics`.
2. **Setup Prometheus**:
   - Configure `prometheus.yml` to scrape `http://localhost:3000/metrics` and `http://localhost:3001/metrics`.
   - Start Prometheus: `prometheus --config.file=prometheus.yml`.
3. **Visualize in Grafana**:
   - Add Prometheus data source.
   - Create dashboards for `http_request_duration_seconds` and `http_requests_total`.

## Troubleshooting

- **Redis Errors**:
  - Verify: `redis-cli ping` (returns `PONG`).
  - Clear Redis: `redis-cli FLUSHALL`.
- **Server Errors**:
  - Check logs: `console.error` in `server-session.js` or `server-jwt.js`.
  - Ensure dependencies: `npm install`.
- **ZAP Issues**:
  - Verify proxy: `127.0.0.1:8080`.
  - Re-run `curl` commands with `--proxy`.
- **Resource Issues**:
  - Monitor: `htop` (`brew install htop` or `sudo apt install htop`).
  - Close apps if RAM <16 GB.

## Notes

- **Security**: The secret (`thesis-secret-123`) is weak. Use a stronger secret (e.g., `crypto.randomBytes(32).toString('hex')`) in production.
- **Thesis Context**: These prototypes support security (ZAP, Burp, Postman) and performance (JMeter) testing for comparing session-based and JWT-based authentication.
- **License**: MIT (or specify your license).