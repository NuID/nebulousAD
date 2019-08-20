# Special thanks to Impacket authors: https://github.com/SecureAuthCorp/impacket
#  __  __                  ______       ____
# /\ \/\ \                /\__  _\     /\  _`\
# \ \ `\\ \  __  __       \/_/\ \/     \ \ \/\ \
#  \ \ , ` \/\ \/\ \  _______\ \ \      \ \ \ \ \
#   \ \ \`\ \ \ \_\ \/\______\\_\ \__  __\ \ \_\ \__
#    \ \_\ \_\ \____/\/______//\_____\/\_\\ \____/\_\
#     \/_/\/_/\/___/          \/_____/\/_/ \/___/\/_/
# Author: Robert Paul, nebulous@nuid.io
# Visit us: https://nuid.io/
# Github: https://github.com/NuID/nebulousAD
# Impacket CLI modified by NuID, Inc. for auditing Active Directory credentials for leaked passwords.
import argparse
import codecs
import logging
import sys
import os
import subprocess
import csv
import json
import datetime
import requests
import shutil
# Import windows utils
import win32gui
import win32con
import _winreg
import win32api
import win32security
import win32evtlog
import win32evtlogutil
from hashlib import sha256
from multiprocessing.dummy import Pool
from multiprocessing import cpu_count
from modimpacket.examples import logger
from tenacity import retry, stop_after_attempt, retry_if_exception_type, wait_random
from modimpacket.examples.secretsdump import LocalOperations, NTDSHashes
from requests.exceptions import ReadTimeout


class WindowsEventWriter:

    def __init__(self):
        # Define event identifiers
        self.__EVT_APP_NAME = "nebulousAD.exe"
        self.__EVT_ID = 4141
        # Define App categories
        self.__Cat_OK_PASS = 1000
        self.__Cat_BAD_PASS = 1001
        # Get SID of user running this audit for event reporting.
        self.__ph = win32api.GetCurrentProcess()
        self.__th = win32security.OpenProcessToken(self.__ph, win32con.TOKEN_READ)
        self.__user_sid = win32security.GetTokenInformation(self.__th, win32security.TokenUser)[0]
        self.__FAIL = win32evtlog.EVENTLOG_AUDIT_FAILURE
        self.__PASS = win32evtlog.EVENTLOG_AUDIT_SUCCESS

    def write_event(self, accountName, isCompromised, auditData):

        if isCompromised:
            EVT_STRS = ["Account failed credential audit!", "Account: {}".format(accountName)]
            EVT_DATA = json.dumps(auditData)
            win32evtlogutil.ReportEvent(self.__EVT_APP_NAME, self.__EVT_ID, self.__Cat_BAD_PASS, eventType=self.__FAIL,
                                        strings=EVT_STRS, data=EVT_DATA, sid=self.__user_sid)
        else:
            EVT_STRS = ["Account passed credential audit.", "Account: {}".format(accountName)]
            EVT_DATA = json.dumps(auditData)
            win32evtlogutil.ReportEvent(self.__EVT_APP_NAME, self.__EVT_ID, self.__Cat_OK_PASS, eventType=self.__PASS,
                                        strings=EVT_STRS, data=EVT_DATA, sid=self.__user_sid)


class DumpSecrets:

    def __init__(self, **kwargs):

        self.__ntdsFile = kwargs.get('ntds')
        self.__systHive = kwargs.get('system')
        self.__history = kwargs.get('history')
        if self.__history is None:
            self.__history = False
        self.__pwdLastSet = kwargs.get('pwd_last_set')
        if self.__pwdLastSet is None:
            self.__pwdLastSet = False
        self.__printUserStatus = kwargs.get('user_status')
        if self.__printUserStatus is None:
            self.__printUserStatus = False
        self.__verbose = kwargs.get('verbose')
        self.__snap = kwargs.get('snap')
        self.__shred = kwargs.get('shred')
        self.__csv = kwargs.get('csv')
        self.__json = kwargs.get('json')
        self.__check = kwargs.get('check')
        self.__apiKey = kwargs.get('apiKey')
        self.__noBackup = kwargs.get('no_backup')
        self.__old_snaps = kwargs.get('old_snaps')
        self.__systemDrive = os.environ['SystemDrive']
        self.__workingDir = "{}\\Program Files\\NuID".format(self.__systemDrive)

        # Required but unused arguments for Impacket's secretsdump lib.
        # isRemote: False, History: True, noLMHash: True, remoteOps: None, useVSSMethod: True, justNTLM: True, pwdLastSet: False, resumeSession: None, outputFileName: None, justUser: None, printUserStatus: True
        self.__isRemote = True
        self.__username = ''
        self.__password = ''
        self.__justDCNTLM = True
        self.__NTDSHashes = None
        self.__isRemote = False
        self.__useVSSMethod = True
        self.__noLMHash = True
        self.__remoteOps = None
        self.__outputFileName = None  # we have our own file output, as csv
        self.__resumeFileName = None
        self.__justUser = None

        # store output of parsing here.
        self.__secrets = None
        # Timestamp when we start
        self.today = datetime.datetime.today()
        """
        Format for the secrets_dict is so:
        {
          "userName": {
            "Status": Enabled|Disabled|N/A,
            "NTLM_Hash": <NTLM Hash>,
            "PwdLastSet": <datetime>,
            "History": {
              "history_0": <NTLM Hash>,
              "history_1": <NTLM Hash>,
              ...
            }, 
            "Check": {
              "LastCheck": <datetime>,
              "Compromised": "True|False|None",
              "Which": [
                "NTLM_Hash", 
                "history_1"
                ]
            }
          },
          ...
        }
        """

    def dump(self):

        if self.__snap:
            path = self.snapshotActiveDirectory()
            self.__ntdsFile = path.get('ntds')
            self.__systHive = path.get('sys_hive')

        if self.__systHive:
            try:
                localOperations = LocalOperations(self.__systHive)
                bootKey = localOperations.getBootKey()
                if self.__ntdsFile:
                    # Grab target's config on LM storage, is the policy set?
                    self.__noLMHash = localOperations.checkNoLMHashPolicy()
            except Exception as e:
                print(e)
        else:
            raise Exception("Need to specify -system <path_to_system_registry_hive>")

        created_date = datetime.datetime.fromtimestamp(os.path.getctime(self.__ntdsFile))
        older_than = self.today - created_date

        if older_than.days > 1:
            # We want to check if the NTDS snapshot is fresh. If it isn't, warn the user.
            logging.warning("Your NTDS Snapshot is over 24 hours old. Any changes made since then will not be audited.")

        self.__NTDSHashes = NTDSHashes(self.__ntdsFile, bootKey, isRemote=self.__isRemote, history=self.__history,
                                       noLMHash=self.__noLMHash, remoteOps=self.__remoteOps,
                                       useVSSMethod=self.__useVSSMethod, justNTLM=self.__justDCNTLM,
                                       pwdLastSet=self.__pwdLastSet, resumeSession=self.__resumeFileName,
                                       outputFileName=self.__outputFileName, justUser=self.__justUser,
                                       printUserStatus=self.__printUserStatus)

        try:

            self.__NTDSHashes.dump()
            self.__secrets = self.__NTDSHashes.secrets_dict

        except Exception as e:
            logging.error(e)

        if self.__verbose:

            for key in self.__secrets:
                nested = self.__secrets[key]
                pwdlastset = nested.get('PwdLastSet')
                status = nested.get('Status')
                hist = nested.get('History')
                nthash = nested.get('NTLM_Hash')

                if pwdlastset is None:
                    pwdlastset = ''

                if hist:
                    history = []
                    for hash in nested.get('History'):
                        history.append(nested.get('History')[hash])
                    history = "History: {}".format(','.join(history))
                else:
                    history = ''

                if status:
                    if status == "Enabled":
                        color = logger.Fore.CYAN
                    else:
                        color = logger.Fore.LIGHTBLACK_EX
                    logging.info(color + "{} ({}): {} {} {}".format(key, status, nthash, pwdlastset, history))
                else:
                    logging.info(logger.Fore.CYAN + "{}: {} {} {}".format(key, nthash, pwdlastset, history))

        logging.info("Found {} account hashes.".format(len(self.__secrets)))

        if self.__check:
            api = NuAPI(self.__apiKey, self.__verbose)
            api.check_hashes(self.__secrets)
            leaked = 0
            for user in self.__secrets:

                if self.__secrets[user]["Check"].get("Compromised"):
                    leaked += 1
            if leaked:
                logging.warning(logger.Fore.LIGHTRED_EX + "{}/{} ".format(leaked, len(self.__secrets)) +
                                "Accounts have leaked credentials!" + logger.Fore.RESET)
            else:
                logging.info(logger.Fore.LIGHTGREEN_EX + "No accounts found to have compromised credentials" +
                             logger.Fore.RESET)

        if self.__csv:
            self.csv_dump(self.__csv)

        if self.__json:
            self.json_dump(self.__json)

        self.cleanup()
        return self.__secrets

    def cleanup(self):

        logging.info('Cleaning up... ')
        if self.__NTDSHashes:
            self.__NTDSHashes.finish()
        if self.__shred:
            self.secure_cleanup()
        if self.__old_snaps:
            self.clean_old_snaps()

    def clean_old_snaps(self):

        now = datetime.datetime.now()
        backup_path = "{}\\snapshot-backups".format(self.__workingDir)

        if self.__shred:

            if self.which("sdelete64.exe"):

                sdelete = "sdelete64.exe"

            elif self.which("sdelete.exe"):

                sdelete = "sdelete.exe"

            else:
                logging.error("Could not find sdelete.exe in PATH. Please install to PATH and rerun -shred. "
                              "You can find this here: https://docs.microsoft.com/en-us/sysinternals/downloads/sdelete")
                sys.exit(1)

        if os.path.exists(backup_path):

            files = os.listdir(backup_path)

            for snap_file in files:
                cdate = datetime.datetime.fromtimestamp(os.path.getctime("{}\\{}".format(backup_path, snap_file)))
                time_diff = now - cdate

                if time_diff.days > self.__old_snaps:

                    if self.__shred:
                        if self.__verbose:
                            logging.warning("Overwriting {} with 7 passes...".format(snap_file))
                        cmd = "{} -p 7 {}".format(sdelete, snap_file)
                        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stdin=subprocess.PIPE)
                        p.stdout.read()
                        p.wait()

                    else:
                        if self.__verbose:
                            logging.warning("Deleting {}...".format(snap_file))
                        os.os.remove("{}\\{}".format(backup_path, snap_file))

    def csv_dump(self, csv_path):
        """
        Dumps the results toa CSV file at the specified path.
        :param csv_path: the full path of the CSV file to ouptut.
        """
        logging.info("Dumping results to CSV file at: {}".format(csv_path))

        with open(csv_path, 'wb') as csvfile:

            fieldnames = [
                'userName',
                'Status',
                'NTLM_Hash',
                'PwdLastSet',
                'History',
                'Compromised',
                'LastCheck',
                'Which'
            ]
            writer = csv.DictWriter(csvfile, fieldnames)
            writer.writeheader()

            for account in self.__secrets:

                nested = self.__secrets[account]
                history = nested.get('History')
                check = nested.get("Check")

                if history:

                    hist_arr = []
                    for hist in history:
                        hist_arr.append("{}:{}".format(hist, history[hist]))
                    hist_out = ','.join(hist_arr)

                else:

                    hist_out = None

                output = {
                    "userName": account,
                    "Status": nested.get('Status'),
                    "NTLM_Hash": nested.get('NTLM_Hash'),
                    "PwdLastSet": nested.get('PwdLastSet'),
                    "History": hist_out,
                    "Compromised": check.get("Compromised"),
                    "LastCheck": self.today.strftime("%Y-%m-%d %H:%M:%S"),
                    "Which": ",".join(check.get("Which"))
                }

                writer.writerow(output)

        csvfile.close()
        logging.info("Done writing to CSV file.")

    def json_dump(self, json_path):
        """
        Dumps the results to a JSON file at the specified path.
        :param json_path: Path to the JSON file to write results to.
        """
        logging.info("Dumping results to JSON file at: {}".format(json_path))
        with open(json_path, 'wb') as f:
            f.write(json.dumps(self.__secrets, indent=4, sort_keys=True))
        f.close()
        logging.info("Done writing to JSON file.")

    def secure_cleanup(self):
        """
        Requires sdelete.exe. Due to irreversibly deleting files, this can only be called with the automated -snap function.
        """
        if self.which("sdelete64.exe"):

            sdelete = "sdelete64.exe"

        elif self.which("sdelete.exe"):

            sdelete = "sdelete.exe"

        else:
            logging.error("Could not find sdelete.exe in PATH. Please install to PATH and rerun -shred. "
                          "You can find this here: https://docs.microsoft.com/en-us/sysinternals/downloads/sdelete")
            sys.exit(1)

        path = "{}\\snapshot".format(self.__workingDir)
        if self.__snap:

            snapshot_files = [
                "{}\\Active Directory\\ntds.dit".format(path),
                "{}\\Active Directory\\ntds.jfm".format(path),
                "{}\\registry\\SYSTEM".format(path),
                "{}\\registry\\SECURITY".format(path)
            ]

            for snap_file in snapshot_files:

                if self.__verbose:
                    logging.warning("Overwriting {} with 7 passes...".format(snap_file))
                cmd = "{} -p 7 {}".format(sdelete, snap_file)
                p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stdin=subprocess.PIPE)
                p.stdout.read()
                p.wait()

            try:
                shutil.rmtree(path)
            except OSError as err:
                logging.error("Unable to wipe directory at {}, Err: {}".format(path, err))

            logging.info("All snapshot files cleaned up.")

    def snapshotActiveDirectory(self):
        """
        Uses ntdsutil.exe to automatically snapshot the SYSTEM registry hive and NTDS.dit file.
        :return: Paths to where the snapshots are stored. Will always be %SYSTEM_DRIVE%\Program Files\NuID\snapshot
        """
        if not os.path.exists(self.__workingDir):
            os.makedirs(self.__workingDir)

        snap_path = "{}\\snapshot".format(self.__workingDir)
        backup_path = "{}\\snapshot-backups".format(self.__workingDir)
        ad_path = "{}\\Active Directory".format(snap_path)
        reg_path = "{}\\registry".format(snap_path)

        if os.path.exists(snap_path):

            if os.listdir(snap_path):

                if not self.__noBackup:
                    logging.info(
                        "{} path is not empty, backing old snapshots and cleaning directory...".format(snap_path))
                    for file in os.listdir(ad_path):

                        ctime = datetime.datetime.fromtimestamp(os.path.getctime("{}\\{}".format(ad_path,
                                                                                                 file))).strftime(
                            "%Y-%m-%d_%H-%M")
                        filename = "{}-{}.bak".format(file, ctime)
                        try:
                            shutil.move("{}\\{}".format(ad_path, file), "{}\\{}".format(backup_path, filename))
                        except IOError as e:
                            os.makedirs(backup_path)
                            shutil.move("{}\\{}".format(ad_path, file), "{}\\{}".format(backup_path, filename))

                    for file in os.listdir(reg_path):
                        ctime = datetime.datetime.fromtimestamp(os.path.getctime("{}\\{}".format(reg_path,
                                                                                                 file))).strftime(
                            "%Y-%m-%d_%H-%M")
                        filename = "{}-{}.bak".format(file, ctime)
                        try:
                            shutil.move("{}\\{}".format(reg_path, file), "{}\\{}".format(backup_path, filename))
                        except IOError as e:
                            os.makedirs(backup_path)
                            shutil.move("{}\\{}".format(reg_path, file), "{}\\{}".format(backup_path, filename))

                if self.__shred:
                    self.secure_cleanup()
                else:
                    shutil.rmtree(snap_path)

        logging.info("Snapping SYSTEM registry hive and NTDS.dit file to {}".format(snap_path))
        logging.warning("Depending on the size of the files, this may take a moment.")

        save = "ntdsutil.exe \"ac i ntds\" \"ifm\" \"create full \\\"{}\\\"\" q q".format(snap_path)
        CMD = subprocess.Popen(save, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)

        CMD.communicate()
        CMD.stderr.read()
        CMD.wait()  # Wait for the snapshot to finish

        return {"ntds": "{}\\ntds.dit".format(ad_path), "sys_hive": "{}\\SYSTEM".format(reg_path)}

    @staticmethod
    def which(program):

        def is_exe(fpath):
            return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

        fpath, fname = os.path.split(program)
        if fpath:
            if is_exe(program):
                return program
        else:
            for path in os.environ["PATH"].split(os.pathsep):
                exe_file = os.path.join(path, program)
                if is_exe(exe_file):
                    return exe_file

        return None


class APIRetryException(Exception):

    def __init__(self):
        pass


class APISystem:

    def __init__(self):

        pass

    @staticmethod
    def set_apiKey(apiKey):
        """
        Sets the API key.
        :param apiKey: Register at https://nuid.io/ for your API key.
        """
        try:
            key = _winreg.ConnectRegistry(None, _winreg.HKEY_CURRENT_USER)
            hkey = _winreg.OpenKey(key, 'Environment', 0, _winreg.KEY_SET_VALUE)

            _winreg.SetValueEx(hkey, 'NUID_API_KEY', 0, _winreg.REG_SZ, apiKey)

            win32gui.SendMessage(win32con.HWND_BROADCAST, win32con.WM_SETTINGCHANGE, 0, 'Environment')

        except Exception as e:
            logging.error("Error installing API Key: {}".format(e))
            sys.exit(1)

        _winreg.CloseKey(key)
        _winreg.CloseKey(hkey)

    @staticmethod
    def read_apiKey():
        """
        Reads the API key from the users Environment Variable.
        :return: Returns the value stored in NUID_API_KEY.
        """
        key = os.environ.get('NUID_API_KEY')
        if key is None:
            logging.error("Could not find API key! "
                          "You may need to log off and back on for the environment variable to be visible to this session. "
                          "Try opening a new cmd.exe?")
            sys.exit(1)

        return key


class NuAPI:

    def __init__(self, apiKey, verbose):

        self.__apiKey = apiKey
        self.__apiHeaders = {"X-NUID-API-KEY": self.__apiKey}  # set our API key in the header as required.
        self.__v = verbose
        self.__api = "https://nebulous.nuid.io"
        self.__secrets = None
        self.__evtLog = WindowsEventWriter()
        # API route: https://nebulous.nuid.io/api/search/hash/NTLMSHA2/<sha256(ntlm)>
        self.__route_url = "https://nebulous.nuid.io/api/search/hash/NTLMSHA2"

    @retry(retry=retry_if_exception_type(APIRetryException), stop=stop_after_attempt(10), wait=wait_random(10, 30))
    def api_helper(self, user):
        """
        Helper function for check_hashes(). Pass over an iterable of the users' keys in __secrets and feed it to this.
        :param user: Pass in the username of the user to look up. This should be a key of __secrets we can use to lookup
        the users information.
        :return: None.
        :raises: APIRetryException @ if the request fails for whatever reason.
        """
        # Broilerplate the data for the Windows Event Log. Need to do this to redact the NT hashes from the log file.
        audit_data = {
            "accoutName": user,
            "Status": self.__secrets[user].get("Status"),
            "Check": {
                "LastCheck": None,
                "Which": [],
                "Compromised": None
            }
        }
        h = sha256()

        # Set the timestamps
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.__secrets[user]['Check']['LastCheck'] = now
        audit_data['Check']['LastCheck'] = now

        if self.__v:
            logging.info(logger.Fore.LIGHTBLACK_EX + "Checking hash for account: {}".format(user,
                                                                                            logger.Fore.RESET))
        try:
            # First we check the accounts active NTLM hash.
            nthash = self.__secrets[user]['NTLM_Hash']
            h.update(nthash)  # Calculate SHA256(NTLM)
            url = "{}/{}".format(self.__route_url, h.hexdigest())
            resp = requests.get(url, headers=self.__apiHeaders, timeout=60)

        except (requests.HTTPError, requests.ConnectTimeout, requests.ConnectionError, ReadTimeout) as err:
            logging.warning("Had trouble connecting to the API. Will retry this request. ERR: {}".format(err))
            raise APIRetryException
        except UnicodeDecodeError as unierr:
            logging.error("Malformated request URL. Did the hash decode correctly? Exiting. {}".format(unierr))
            exit(1)

        if resp.status_code == 200:
            logging.warning(logger.Fore.LIGHTRED_EX + "CURRENT PASSWORD for account: {} is COMPROMISED!".format(user) +
                            logger.Fore.RESET)

            self.__secrets[user]["Check"]["Compromised"] = True
            self.__secrets[user]["Check"]["Which"].append("NTLM_Hash")

        elif resp.status_code == 404:
            if self.__v:
                logging.info(logger.Fore.LIGHTBLACK_EX + "Hash for account:"
                                                         " {} is OK.{}".format(user,  logger.Fore.RESET))
            self.__secrets[user]["Check"]["Compromised"] = False
        elif resp.status_code == 429:
            logging.warning("We are being rate limited. Retrying request and throttling connection.")
            raise APIRetryException
        elif resp.status_code == 500:
            logging.error("API error. Retrying the request. Code: {}".format(resp.status_code))
            raise APIRetryException

        if self.__secrets[user].get("History"):
            # Need to split this one up so we can retry each individual request. Should prevent log spam from retrying.
            self.check_history(user)
            audit_data['Check']['Which'] = self.__secrets[user]['Check']['Which']

        # Setup the data to be submitted to the audit log.
        audit_data['Check']['Compromised'] = self.__secrets[user]['Check']['Compromised']
        audit_data['Check']['Which'] = self.__secrets[user]['Check']['Which']
        # Write our results and redacted data to the Windows event log.
        self.__evtLog.write_event(user, audit_data['Check']['Compromised'], audit_data)

        return 0

    @retry(retry=retry_if_exception_type(APIRetryException), stop=stop_after_attempt(10), wait=wait_random(10, 30))
    def check_history(self, user):
        """
        We split up check_history to its own function. This way if we get a failure when checking an old hash, it does
        not restart the entire process. However, if we get a failure, it will restart all of the history over again.
        :param user: Pass in the username of the user to look up. This should be a key of __secrets we can use to lookup
        the users information.
        :return: None.
        :raises: APIRetryException @ if the request fails for whatever reason.
        """
        # TODO: Get better exception handling so we don't retry all histories if one fails or gets rate limited.
        for nthistory in self.__secrets[user]["History"]:

            h = sha256()
            ntlm_hist = self.__secrets[user]["History"][nthistory]
            h.update(ntlm_hist)

            if self.__v:

                logging.info(logger.Fore.LIGHTBLACK_EX + "Checking {} for user: {}...".format(nthistory, user) +
                             logger.Fore.RESET)

            try:
                url = "{}/{}".format(self.__route_url, h.hexdigest())
                resp = requests.get(url, headers=self.__apiHeaders, timeout=60)
            except (requests.HTTPError, requests.ConnectTimeout, requests.ConnectionError, ReadTimeout) as err:
                logging.warning("Had trouble connecting to the API. Will retry this request. ERR: {}".format(err))
                raise APIRetryException
            if resp.status_code == 200:
                logging.warning(logger.Fore.RED + "Historic Hash {} for account: {} is INACTIVE and "
                                                  "COMPROMISED!".format(nthistory, user) + logger.Fore.RESET)
                self.__secrets[user]["Check"]["Compromised"] = True
                self.__secrets[user]["Check"]["Which"].append(nthistory)

            elif resp.status_code == 404:
                if self.__v:
                    logging.info(
                        logger.Fore.LIGHTBLACK_EX + "Historic hash {} for account:"
                                                    " {} is OK. {}".format(nthistory, user, logger.Fore.RESET))

            elif resp.status_code == 429:
                logging.warning("We are being rate limited. Retrying request and throttling connection.")
                raise APIRetryException

    def check_hashes(self, secrets):
        """
        Feed this a secrets_dict from secretsdump.py and we can check against NuID's api if the hash exists.
        :param secrets: secrets_dict object from secretsdump.NTDSHashes().
        :return: Return the updated secrets_dict, after all checks have completed.
        """
        self.__secrets = secrets
        # Use a minumum of 16 threads for network bound I/O. More if we have them.
        if cpu_count() < 16:
            procs = 16
        else:
            procs = cpu_count()
        p = Pool(processes=procs)
        logging.info("Checking a total of {} accounts for compromised credentials.".format(len(self.__secrets)))

        p.imap_unordered(self.api_helper, self.__secrets)

        p.close()
        p.join()
        logging.info("Done checking hashes.")
        return self.__secrets


def check_positive_int(n):
    """
    Type checking for the -clean-old-snaps argument.
    :param n: whatever the user entered for the -clean-old-snaps arg.
    :return: return the object back if it is an integer, and is > 0, else raise.
    :raises: argparse.ArgumentTypeErr, ValueError
    """
    try:
        n = int(n)
    except ValueError as err:
        # ya done fucked up
        logging.error("-clean-old-snaps requires an number.")
    if n <= 1:
        raise argparse.ArgumentTypeError("Must specify a positive integer for -clean-old-snaps!")
    return n


def main():

    banner = """
 __  __                  ______       ____         
/\\ \\/\\ \\                /\\__  _\\     /\\  _`\\       
\\ \\ `\\\\ \\  __  __       \\/_/\\ \\/     \\ \\ \\/\\ \\     
 \\ \\ , ` \\/\\ \\/\\ \\  _______\\ \\ \\      \\ \\ \\ \\ \\    
  \\ \\ \\`\\ \\ \\ \\_\\ \\/\\______\\\\_\\ \\__  __\\ \\ \\_\\ \\__ 
   \\ \\_\\ \\_\\ \\____/\\/______//\\_____\\/\\_\\\\ \\____/\\_\\
    \\/_/\\/_/\\/___/          \\/_____/\\/_/ \\/___/\\/_/


    \tNu_I.D. BREACH CREDENTIAL AUDITOR
    \t\tUsing: Impacket v0.9.19
    """
    # Init terminal colors
    print(logger.Fore.LIGHTGREEN_EX + banner + logger.Fore.RESET)

    logger.init()
    logging.getLogger().setLevel(logging.INFO)  # Log level debug in Impacket is too spammy, force it to INFO.
    # Explicitly changing the stdout encoding format
    if sys.stdout.encoding is None:
        # Output is redirected to a file
        sys.stdout = codecs.getwriter('utf8')(sys.stdout)

    parser = argparse.ArgumentParser(add_help=True,
                                     description="{}NuID Credential Auditing tool.{}".format(logger.Fore.GREEN,
                                                                                             logger.Fore.RESET))
    # Add args
    parser.add_argument('-ntds', action='store', help='NTDS.DIT file to parse')
    parser.add_argument('-system', action='store', help='SYSTEM registry hive to parse')
    parser.add_argument('-csv', action='store', help='Output results to CSV file at this PATH.')
    parser.add_argument('-json', action='store', help='Output results to JSON file at this PATH')
    parser.add_argument('-init-key', action='store', help="Install your Nu_I.D. API key to the current users PATH.")
    parser.add_argument('-c', '--check', action='store_true', default=False,
                        help="Check against Nu_I.D. API for compromised credentials.{}".format(
                            logger.Fore.LIGHTGREEN_EX))
    parser.add_argument('-snap', action='store_true', default=False,
                        help="{}Use ntdsutil.exe to snapshot the system registry hive and ntds.dit file to "
                             "<systemDrive>:\\Program Files\\NuID\\{}".format(logger.Fore.GREEN, logger.Fore.RESET))
    parser.add_argument('-shred', action='store_true', default=False,
                        help="When performing delete operations on files, use a 7 pass overwrite with sdelete.exe. "
                             "Download here: https://docs.microsoft.com/en-us/sysinternals/downloads/sdelete")
    parser.add_argument('-no-backup', action='store_true', default=False,
                        help="Do not backup the existing snapshots, just overwrite them instead.")
    parser.add_argument('-clean-old-snaps', action='store', type=check_positive_int,
                        help="Clean backups older than N days.")

    group = parser.add_argument_group('display options')

    group.add_argument('-user-status', action='store_true', default=False,
                       help='Display whether or not the user is disabled')
    group.add_argument('-pwd-last-set', action='store_true', default=False,
                       help='Shows pwdLastSet attribute for each account found within the NTDS.DIT database.')
    group.add_argument('-history', action='store_true', default=False,
                       help='Dump NTLM hash history of the users.')
    group.add_argument('-v', action='store_true', default=False,
                       help='Enable verbose mode.')

    args = parser.parse_args()

    api_system = APISystem()
    if args.init_key:
        api_system.set_apiKey(args.init_key)

    apiKey = api_system.read_apiKey()

    if args.v:
        logging.info("Using API Key: {}".format(apiKey))

    if (args.ntds and args.system) or args.snap:
        hashdump = DumpSecrets(ntds=args.ntds, system=args.system, user_status=args.user_status, json=args.json,
                               pwd_last_set=args.pwd_last_set, history=args.history, verbose=args.v, csv=args.csv,
                               shred=args.shred, check=args.check, snap=args.snap, no_backup=args.no_backup,
                               old_snaps=args.clean_old_snaps, apiKey=apiKey)

        hashdump.dump()

    else:
        logging.info('Must specify both -ntds and -system, or -snap for dumping system hashes. Exiting.')
        sys.exit(1)
