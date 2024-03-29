# To use:
# 1.  Install `pywin32` to the global `site-packages`
#        pip install pywin32
# 2.  Install the service:
#        python service_test_tokenser.py install
# 3.  Run the pywin32 post-install script:
#        pywin32_postinstall.py -install
# 4.  To delete the service when done:
#      a) sc query state=all > service-list.txt
#      b) Find your service in the list, and get the SERVICE_NAME
#          The SERVICE_NAME should match the _svc_name in the class below
#      c) sc delete <SERVICE_NAME>

import win32serviceutil
import win32service
import win32event
import servicemanager
import socket

import concurrent.futures
import logging
import subproc_test
from subproc_test_token import run

logger = logging.getLogger()

logging.basicConfig(
    filename = r"C:\Users\Administrator\GitHub\Win32Impersonation\service-token-test-log.txt",
    level = logging.DEBUG, 
    format = '%(asctime)s [%(levelname)-7.7s] %(message)s'
)

def run_subproc() -> None:
    logger.info("run_subproc is on the go")
    try:
        run()
    except Exception as e:
        logger.exception(f"Exception in run_subproc: {e}")

class TestingService(win32serviceutil.ServiceFramework):
    _future = None
    _svc_name_ = "TESTING_TokenService"
    _svc_display_name_ = "TESTING Token Service"
   
    def __init__(self,args):
        win32serviceutil.ServiceFramework.__init__(self,args)
        self.stop_event = win32event.CreateEvent(None,0,0,None)
        socket.setdefaulttimeout(60)

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.stop_event)
        logger.info('Stopping service ...')

    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_,'')
        )
        logger.info("Service starting...")
        with concurrent.futures.ThreadPoolExecutor() as threadpool:
            logger.info("Submitting future")
            self._future = threadpool.submit(run_subproc)
            logger.info("Future submitted")

            while True:
                logger.info("Polling...")
                if not win32event.WaitForSingleObject(self.stop_event, 1000):
                    logger.info("Stop event recieved!")
                    if subproc_test.popen_instance:
                        subproc_test.popen_instance.terminate()
                        subproc_test.popen_instance.stdout.close()
                    else:
                        logging.warning("Could not find subprocess_test.popen_instance")
                if self._future.done():
                    logger.info("Future is done")
                    try:
                        self._future.result()
                    except Exception as e:
                        logging.exception(f"Future failed: {e}")
                    break

        logger.info("Sending stop to Windows Service Controller")
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STOPPED,
            (self._svc_name_,'')
        )


if __name__ == '__main__':
    try:
        win32serviceutil.HandleCommandLine(TestingService)
    except Exception as e:
        logging.exception(e)