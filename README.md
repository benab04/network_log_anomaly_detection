# Django Server Setup Guide

## Prerequisites

### 1. Python Installation

#### Windows

1. Download Python from [python.org](https://www.python.org/downloads/)
2. Run the installer and check "Add Python to PATH"
3. Verify installation: `python --version`

#### macOS

1. Using Homebrew: `brew install python`
2. Or download from [python.org](https://www.python.org/downloads/)
3. Verify installation: `python3 --version`

#### Linux

```bash
sudo apt update  # Ubuntu/Debian
sudo apt install python3
# or
sudo dnf install python3  # Fedora
```

## Project Setup

1. Clone the repository:

```bash
git clone https://github.com/benab04/network_log_anomaly_detection
cd network_log_anomaly_detection
```

2. Create a virtual environment:

```bash
# Windows
python -m venv venv
.\venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Database setup:

```bash
python manage.py migrate
```

## Running the Server

1. Start the development server:

```bash
python manage.py runserver
```

The server will start at `http://127.0.0.1:8000/`

## Important Settings

- The server is configured to allow all CORS origins
- Debug mode is enabled by default
- Django Attack Blocker library is pre-configured and used in few endpoints as an example

## Attack Blocker Configuration

To enable the attack blocker:

1. Ensure you have the required model file (`model.joblib`) and the encoder file (`encoder.pkl`)

## API Endpoints

- `/` - Home page
- `/blocker/` - Test endpoint
- `/temporary_blocker/` - Temporary block test endpoint
- `/get_stats/` - Get blocker statistics
- `/block_ip/` - Manually block an IP
- `/unblock_ip/` - Manually unblock an IP

## Security Notes

- For production deployment:
  - Change `DEBUG` to `False`
  - Update `SECRET_KEY`
  - Configure proper `ALLOWED_HOSTS`
  - Enable CSRF protection
  - Set up proper database configuration

## API Testing Guide (Using Insomnia)

### Setting Up Insomnia

1. Download and install [Insomnia](https://insomnia.rest/)
2. Create a new Collection for the project

### Testing Endpoints

1. **Home Page**

   - Method: GET
   - URL: `http://localhost:8000/`
   - Expected Response: **200 OK**

   ```json
   { "message": "Welcome to the home page!" }
   ```

2. **Test Blocker**

   - Method: GET
   - URL: `http://localhost:8000/blocker/`
   - Body

     > **Note:** This is an example of a normal log from the UNSW dataset and will not be blocked by the library.

   ```json
   {
     "log": {
       "dur": 0.0000000000000008888888444,
       "proto": 0,
       "service": 0,
       "state": 1,
       "spkts": 1,
       "dpkts": 0,
       "sbytes": 2048,
       "dbytes": 0,
       "rate": 0,
       "sttl": 64,
       "dttl": 64,
       "sload": 0.0,
       "dload": 0.0,
       "sloss": 0,
       "dloss": 0,
       "sinpkt": 0.0,
       "dinpkt": 0.0,
       "sjit": 0.0,
       "djit": 0.0,
       "swin": 65535,
       "dwin": 65535,
       "stcpb": 0,
       "dtcpb": 0,
       "tcprtt": 0.0,
       "synack": 0.0,
       "ackdat": 0.0,
       "smean": 2048,
       "dmean": 0,
       "trans_depth": 1,
       "response_body_len": 0,
       "ct_srv_src": 1,
       "ct_state_ttl": 1,
       "ct_dst_ltm": 1,
       "ct_src_dport_ltm": 1,
       "ct_dst_sport_ltm": 1,
       "ct_dst_src_ltm": 1,
       "ct_src_ltm": 1,
       "ct_srv_dst": 1,
       "is_ftp_login": 0,
       "ct_ftp_cmd": 0,
       "ct_flw_http_mthd": 1,
       "is_sm_ips_ports": 0
     }
   }
   ```

   - Expected Response: **200 OK**

   ```json
   {
     "message": "Welcome to the django attack blocker testing page!"
   }
   ```

3. **Temporary Block Test**

   - Method: GET
   - URL: `http://localhost:8000/temporary_blocker/`
   - Body

     > **Note:** This is an example of an attack log from the UNSW dataset and will be blocked by the library.

   ```json
   {
     "log": {
       "id": 57912,
       "dur": 0.266185,
       "proto": "tcp",
       "service": "http",
       "state": "FIN",
       "spkts": 10,
       "dpkts": 8,
       "sbytes": 942,
       "dbytes": 2350,
       "rate": 63.86536,
       "sttl": 62,
       "dttl": 252,
       "sload": 25486.03516,
       "dload": 61821.66797,
       "sloss": 2,
       "dloss": 2,
       "sinpkt": 29.576111,
       "dinpkt": 37.007145,
       "sjit": 1465.12011,
       "djit": 55.170531,
       "swin": 255,
       "stcpb": 4170099405,
       "dtcpb": 1363141949,
       "dwin": 255,
       "tcprtt": 0.051933,
       "synack": 0.006382,
       "ackdat": 0.045551,
       "smean": 94,
       "dmean": 294,
       "trans_depth": 1,
       "response_body_len": 774,
       "ct_srv_src": 2,
       "ct_state_ttl": 1,
       "ct_dst_ltm": 1,
       "ct_src_dport_ltm": 1,
       "ct_dst_sport_ltm": 1,
       "ct_dst_src_ltm": 1,
       "is_ftp_login": 0,
       "ct_ftp_cmd": 0,
       "ct_flw_http_mthd": 1,
       "ct_src_ltm": 1,
       "ct_srv_dst": 1,
       "is_sm_ips_ports": 0,
       "attack_cat": "Exploits",
       "label": 1
     }
   }
   ```

   - Expected Response: **403 Forbidden** (temporarily blocked)

   ```json
   {
     "error": "Access denied",
     "message": "Your request has been blocked"
   }
   ```

4. **Get Statistics**

   - Method: GET
   - URL: `http://localhost:8000/get_stats/`
   - Expected Response: **200 OK**

   ```json
   {
     "total_requests": 0,
     "blocked_requests": 0,
     "allowed_requests": 0,
     "model_failures": 0,
     "cache_hits": 0
   }
   ```

5. **Block IP**

   - Method: POST
   - URL: `http://localhost:8000/block_ip/`
   - Body (Optional, if empty, permanently blocks the IP of origin)

   ```json
    {
        "ip":192.168.1.1,
        "duration" : 20
    }
   ```

   - Expected Response: **200 OK**

   ```json
   {
     "message": "IP blocked successfully."
   }
   ```

6. **Unblock IP**
   - Method: POST
   - URL: `http://localhost:8000/unblock_ip/`
   - Body (Optional, if empty, unblocks the IP of origin):
   ```json
   {
     "ip": "192.168.1.1"
   }
   ```
   - Expected Response: **200 OK**
   ```json
   {
     "message": "IP unblocked successfully."
   }
   ```

## Production and Deployment

The steps for production and deployment are similar to the development setup, with a slight change in the command used to start the server.

To start the server in production, use the following command:

```bash
gunicorn server.wsgi
```

If you encounter issues such as memory limitations, use this alternative command:

```bash
gunicorn --config gunicorn_config.py server.wsgi
```

The `gunicorn_config.p` is present in the root directory of the folder(where `manage.py` is present) and it contains additional commands to configure gunicorn.

- A production server has been deployed on Render following the above steps at
  [https://network-log-anomaly-detection.onrender.com](https://network-log-anomaly-detection.onrender.com).
- This server would take around 50 seconds to boot up (free tier production server)
