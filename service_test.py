# To use:
# 1.  Install `pywin32` and `openjd-sessions` to the global `site-packages`
#        pip install pywin32
# 2.  Install the service:
#        python service_test.py install
# 3.  Run the pywin32 post-install script:
#        pywin32_postinstall.py -install

import win32serviceutil
import win32service
import win32event
import servicemanager

import concurrent.futures
import logging
from subproc_test import run, popen_instance

logger = logging.getLogger()

logging.basicConfig(
    filename = r"C:\Users\Administrator\ServiceExperimentation\Feb24\service-test-log.txt",
    level = logging.DEBUG, 
    format = '%(asctime)s [%(levelname)-7.7s] %(message)s'
)

def run_subproc() -> None:
    try:
        run()
    except Exception as e:
        logger.exception("Exception!")

class OpenJDService(win32serviceutil.ServiceFramework):
    _svc_name_ = "OpenJDServiceTest_Feb24"
    _svc_display_name_ = "OpenJD Service Prototype - Feb24"
    _stop_requested = False

    _threadpool = None
    _future = None

   
    def __init__(self,args):
        win32serviceutil.ServiceFramework.__init__(self,args)
        self.stop_event = win32event.CreateEvent(None,0,0,None)
        socket.setdefaulttimeout(60)
        self.stop_requested = False

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.stop_event)
        # logger.info('Stopping service ...')
        self.stop_requested = True

    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_,'')
        )
        #logger.info("Service starting...")
        # self._threadpool = concurrent.futures.ThreadPoolExecutor()
        #logger.info("Submitting future")
        #self._future = self._threadpool.submit(run_subproc)
        #logger.info("Future submitted")

        # while True:
        #     if win32event.WaitForSingleObject(self.ev_stop, 1000):
        #         logger.info("Stop event recieved!")
        #         popen_instance.terminate()
            # if self._future.done():
            #     logger.info("Future is done")
            #     try:
            #         self._future.result()
            #     except Exception as e:
            #         logging.exception("Future failed")
            #         break

        #logger.info("Sending stop to Windows Service Controller")
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STOPPED,
            (self._svc_name_,'')
        )


if __name__ == '__main__':
    try:
        win32serviceutil.HandleCommandLine(OpenJDService)
    except Exception as e:
        logging.exception(e)