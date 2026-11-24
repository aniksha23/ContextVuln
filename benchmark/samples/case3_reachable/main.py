from urllib3.util.retry import Retry
retry_strategy = Retry(total=3, backoff_factor=0.5)
