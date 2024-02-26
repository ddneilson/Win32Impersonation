from subproc_test import run
import logging

logger = logging.getLogger()

logging.basicConfig(
    filename = r"C:\Users\Administrator\GitHub\Win32Impersonation\local-test-log.txt",
    level = logging.DEBUG, 
    format = '%(asctime)s [%(levelname)-7.7s] %(message)s'
)

if __name__ == "__main__":
    run()