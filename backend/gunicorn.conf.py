import multiprocessing

workers = min(2, multiprocessing.cpu_count())
worker_class = "sync"
timeout = 120
keepalive = 5
max_requests = 1000
max_requests_jitter = 100
accesslog = "-"
errorlog = "-"
loglevel = "info"
forwarded_allow_ips = "*"
