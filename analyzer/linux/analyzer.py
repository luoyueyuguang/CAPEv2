# Copyright (C) 2015-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import datetime
import logging
import os
import pkgutil
import sys
import tempfile
import time
import traceback
import zipfile
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import urlopen

from lib.api.process import Process
from lib.common.abstracts import Auxiliary
from lib.common.constants import PATHS
from lib.common.exceptions import CuckooError, CuckooPackageError
from lib.common.results import upload_to_host
from lib.core.config import Config
from lib.core.packages import choose_package_class
from lib.core.startup import create_folders, init_logging
from modules import auxiliary

log = logging.getLogger()

PID = os.getpid()
FILES_LIST = set()
DUMPED_LIST = set()
PROCESS_LIST = set()
SEEN_LIST = set()
PPID = Process(pid=PID).get_parent_pid()


def add_pids(pids):
    """Add PID."""
    if not isinstance(pids, (tuple, list, set)):
        pids = [pids]

    for pid in pids:
        log.info("Added new process to list with pid: %s", pid)
        pid = int(pid)
        if pid not in SEEN_LIST:
            PROCESS_LIST.add(pid)
        SEEN_LIST.add(pid)


def dump_files():
    """Dump all the dropped files."""
    for file_path in FILES_LIST:
        log.info("PLS IMPLEMENT DUMP, want to dump %s", file_path)


class Analyzer:
    """Cuckoo Linux Analyzer.

    This class handles the initialization and execution of the analysis
    procedure, including the auxiliary modules and the analysis packages.
    """

    def __init__(self):
        self.target = None

    def prepare(self):
        """Prepare env for analysis."""

        # Create the folders used for storing the results.
        create_folders()

        # Initialize logging.
        init_logging()

        # Parse the analysis configuration file generated by the agent.
        self.config = Config(cfg="analysis.conf")
        self.options = self.config.get_options()

        if self.config.get("clock"):
            # Set virtual machine clock.
            clock = datetime.datetime.strptime(self.config.clock, "%Y%m%dT%H:%M:%S")
            # Setting date and time.
            os.system(f'date -s "{clock.strftime("%y-%m-%d %H:%M:%S")}"')

        # We update the target according to its category. If it's a file, then
        # we store the path.
        if self.config.category == "file":
            self.target = os.path.join(tempfile.gettempdir(), self.config.file_name)
        # If it's a URL, well.. we store the URL.
        elif self.config.category == "archive":
            zip_path = os.path.join(os.environ.get("TEMP", "/tmp"), self.config.file_name)
            with zipfile.ZipFile(zip_path) as zf:
                zf.extractall(os.environ.get("TEMP", "/tmp"))
            self.target = os.path.join(os.environ.get("TEMP", "/tmp"), self.config.options["filename"])
        else:
            self.target = self.config.target

    def complete(self):
        """End analysis."""
        # Dump all the notified files.
        dump_files()

        # Hell yeah.
        log.info("Analysis completed")
        return True

    def run(self):
        """Run analysis.
        @return: operation status.
        """
        self.prepare()

        log.debug("Starting analyzer from: %s", Path.cwd())
        log.debug("Storing results at: %s", PATHS["root"])

        # If no analysis package was specified at submission, we try to select
        # one automatically.
        """
        if not self.config.package:
            log.debug("No analysis package specified, trying to detect it automagically")

            package = "generic" if self.config.category == "file" else "wget"

            # If we weren't able to automatically determine the proper package,
            # we need to abort the analysis.
            if not package:
                raise CuckooError(f"No valid package available for file type: {self.config.file_type}")

            log.info('Automatically selected analysis package "%s"', package)
        # Otherwise just select the specified package.
        else:
            package = self.config.package

        # Generate the package path.
        package_name = f"modules.packages.{package}"

        # Try to import the analysis package.
        try:
            __import__(package_name, globals(), locals(), ["dummy"], 0)
        # If it fails, we need to abort the analysis.
        except ImportError:
            raise CuckooError('Unable to import package "{package_name}", does not exist')

        # Initialize the package parent abstract.
        Package()

        # Enumerate the abstract subclasses.
        try:
            package_class = Package.__subclasses__()[0]
        except IndexError as e:
            raise CuckooError(f"Unable to select package class (package={package_name}): {e}")
        """
        if self.config.package:
            suggestion = "ff" if self.config.package == "ie" else self.config.package
        elif self.config.category != "file":
            suggestion = "url"
        else:
            suggestion = None

        # Try to figure out what analysis package to use with this target
        kwargs = {"suggestion": suggestion}
        if self.config.category == "file":
            package_class = choose_package_class(self.config.file_type, self.config.file_name, **kwargs)
        else:
            package_class = choose_package_class(None, None, **kwargs)

        if not package_class:
            raise Exception("Could not find an appropriate analysis package")
        # Package initialization
        kwargs = {"options": self.config.options, "timeout": self.config.timeout, "strace_ouput": PATHS["logs"]}

        # Initialize the analysis package.
        # pack = package_class(self.config.get_options())
        pack = package_class(self.target, **kwargs)
        # Initialize Auxiliary modules
        Auxiliary()
        prefix = f"{auxiliary.__name__}."
        for loader, name, ispkg in pkgutil.iter_modules(auxiliary.__path__, prefix):
            if ispkg:
                continue

            # Import the auxiliary module.
            try:
                log.debug('Importing auxiliary module "%s"...', name)
                __import__(name, globals(), locals(), ["dummy"], 0)
            except ImportError as e:
                log.warning('Unable to import the auxiliary module "%s": %s', name, e)

        # Walk through the available auxiliary modules.
        aux_enabled, aux_avail = [], []
        for module in sorted(Auxiliary.__subclasses__(), key=lambda x: x.priority, reverse=True):
            # Try to start the auxiliary module.
            try:
                aux = module(self.options, self.config)
                log.debug('Initialized auxiliary module "%s"', module.__name__)
                aux_avail.append(aux)
                log.debug('Trying to start auxiliary module "%s"...', module.__name__)
                aux.start()
                log.debug('Started auxiliary module "%s"', module.__name__)
                aux_enabled.append(aux)
            except (NotImplementedError, AttributeError):
                log.warning("Auxiliary module %s was not implemented", module.__name__)
            except Exception as e:
                log.warning("Cannot execute auxiliary module %s: %s", module.__name__, e)

        # Start analysis package. If for any reason, the execution of the
        # analysis package fails, we have to abort the analysis.
        try:
            # pids = pack.start(self.target)
            pids = pack.start()
        except NotImplementedError:
            raise CuckooError(f'The package "{package_class}" doesn\'t contain a run function')
        except CuckooPackageError as e:
            raise CuckooError(f'The package "{package_class}" start function raised an error: {e}')
        except Exception as e:
            raise CuckooError(f'The package "{package_class}" start function encountered an unhandled exception: {e}')

        # If the analysis package returned a list of process IDs, we add them
        # to the list of monitored processes and enable the process monitor.
        if pids:
            add_pids(pids)
            pid_check = True

        # If the package didn't return any process ID (for example in the case
        # where the package isn't enabling any behavioral analysis), we don't
        # enable the process monitor.
        else:
            log.info("No process IDs returned by the package, running for the full timeout")
            pid_check = False

        # Check in the options if the user toggled the timeout enforce. If so,
        # we need to override pid_check and disable process monitor.
        if self.config.enforce_timeout:
            log.info("Enabled timeout enforce, running for the full timeout")
            pid_check = False

        time_counter = 0

        while True:
            time_counter += 1
            if time_counter > int(self.config.timeout):
                log.info("Analysis timeout hit, terminating analysis")
                break

            try:
                # If the process monitor is enabled we start checking whether
                # the monitored processes are still alive.
                if pid_check:
                    for pid in list(PROCESS_LIST):
                        if not Process(pid=pid).is_alive():
                            log.info("Process with pid %s has terminated", pid)
                            PROCESS_LIST.remove(pid)

                    # ToDo
                    # ask the package if it knows any new pids
                    # add_pids(pack.get_pids())

                    # also ask the auxiliaries
                    for aux in aux_avail:
                        add_pids(aux.get_pids())

                    # If none of the monitored processes are still alive, we
                    # can terminate the analysis.
                    if not PROCESS_LIST:
                        log.info("Process list is empty, terminating analysis")
                        break

                    # Update the list of monitored processes available to the
                    # analysis package. It could be used for internal
                    # operations within the module.
                    pack.set_pids(PROCESS_LIST)

                try:
                    # The analysis packages are provided with a function that
                    # is executed at every loop's iteration. If such function
                    # returns False, it means that it requested the analysis
                    # to be terminate.
                    if not pack.check():
                        log.info("The analysis package requested the termination of the analysis")
                        break

                # If the check() function of the package raised some exception
                # we don't care, we can still proceed with the analysis but we
                # throw a warning.
                except Exception as e:
                    log.warning('The package "%s" check function raised an exception: %s', package_class, e)
            except Exception as e:
                log.exception("The PID watching loop raised an exception: %s", e)
            finally:
                # Zzz.
                time.sleep(1)

        try:
            # Before shutting down the analysis, the package can perform some
            # final operations through the finish() function.
            pack.finish()
        except Exception as e:
            log.warning('The package "%s" finish function raised an exception: %s', package_class, e)

        try:
            # Upload files the package created to files in the results folder
            package_files = pack.package_files()
            if package_files is not None:
                for package in package_files:
                    upload_to_host(package[0], os.path.join("files", package[1]))
        except Exception as e:
            log.warning('The package "%s" package_files function raised an exception: %s', package_class, e)
        try:
            # Upload the strace logs to host
            for file in os.listdir(PATHS["logs"]):
                upload_to_host(os.path.join(PATHS["logs"], file), os.path.join("logs", file))
        except Exception as e:
            log.warning('The strace log failed to transfer:', e)

        # Terminate the Auxiliary modules.
        log.info("Stopping auxiliary modules")
        for aux in sorted(aux_enabled, key=lambda x: x.priority):
            try:
                log.info("Stopping auxiliary module: %s", aux.__class__.__name__)
                aux.stop()
            except (NotImplementedError, AttributeError):
                continue
            except Exception as e:
                log.warning("Cannot terminate auxiliary module %s: %s", aux.__class__.__name__, e)

        log.info("Finishing auxiliary modules")
        if self.config.terminate_processes:
            # Try to terminate remaining active processes. We do this to make sure
            # that we clean up remaining open handles (sockets, files, etc.).
            log.info("Terminating remaining processes before shutdown")

            for pid in PROCESS_LIST:
                proc = Process(pid=pid)
                if proc.is_alive():
                    try:
                        proc.terminate()
                    except Exception:
                        continue

        # Run the finish callback of every available Auxiliary module.
        for aux in aux_avail:
            try:
                aux.finish()
            except (NotImplementedError, AttributeError):
                continue
            except Exception as e:
                log.warning("Exception running finish callback of auxiliary module %s: %s", aux.__class__.__name__, e)

        # Let's invoke the completion procedure.
        self.complete()

        return True


if __name__ == "__main__":
    success = False
    error = ""
    data = {}

    try:
        # Initialize the main analyzer class.
        analyzer = Analyzer()

        # Run it and wait for the response.
        success = analyzer.run()

    # This is not likely to happen.
    except KeyboardInterrupt:
        error = "Keyboard Interrupt"

    # If the analysis process encountered a critical error, it will raise a
    # CuckooError exception, which will force the termination of the analysis.
    # Notify the agent of the failure. Also catch unexpected exceptions.
    except Exception as e:
        # Store the error.
        error_exc = traceback.format_exc()
        error = str(e)

        # Just to be paranoid.
        if len(log.handlers):
            log.exception(error_exc)
        else:
            sys.stderr.write(f"{error_exc}\n")

    # Once the analysis is completed or terminated for any reason, we report
    # back to the agent, notifying that it can report back to the host.
    finally:
        try:
            data = {
                "status": "complete",
                "description": success,
            }
            with urlopen("http://127.0.0.1:8000/status", urlencode(data).encode()) as response:
                response.read()
        except Exception as e:
            print(e)
