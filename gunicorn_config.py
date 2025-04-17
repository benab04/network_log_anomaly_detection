# gunicorn_config.py

# Server socket
bind = '0.0.0.0:8000'

# Worker processes
workers = 1  # Reduce number of workers to save memory
worker_class = 'gevent'  # Use async worker class for better performance with fewer workers
worker_connections = 1000

# Restart workers after handling this many requests
max_requests = 1000
max_requests_jitter = 50  # Add jitter to prevent all workers restarting at once

# Logging
loglevel = 'info'
accesslog = '-'  # Log to stdout
errorlog = '-'   # Log errors to stdout

# Timeout configuration
timeout = 120  # Increase timeout if your app needs more time to load

# Prevent memory leaks by limiting request size
limit_request_line = 4096
limit_request_fields = 100
limit_request_field_size = 8190