import multiprocessing

# Render free tier has 1 CPU — keep workers low to avoid OOM
workers          = 2
worker_class     = "sync"
timeout          = 120          # kill workers stuck > 2 min
keepalive        = 5
max_requests     = 500          # recycle workers to prevent memory leaks
max_requests_jitter = 50
accesslog        = "-"
errorlog         = "-"
loglevel         = "info"
forwarded_allow_ips = "*"       # trust Render's proxy headers
preload_app      = True         # load app once, share across workers (saves RAM)
