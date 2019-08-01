NuID Active Directory Hashcheck Tool
=================================
### Installation

Simply download the precompiled release (requires no python interpreter), or build from source:

Requires Python2.7 (for now)

Run `git clone <publicGitRepo>`

Next, install with `python setup.py install`

Then initialize your key. You can get your key by visiting: https://nebulous.nuid.io/#/register
Once registered, click the button to generate your API key and copy it.

Now you can initialize them like so: `nebulousAD -init-key <api_key>`

You can now run the tool. If it can't find your API key, you may need to restart your terminal session. 
The API key is stored in an environment variable.  

### Usage
Example to dump all hashes and check them against NuID's api:
`nebulousAD.exe -v -snap -check`

```
NuID Credential Auditing tool.

optional arguments:
  -h, --help            show this help message and exit
  -ntds NTDS            NTDS.DIT file to parse
  -system SYSTEM        SYSTEM registry hive to parse
  -csv CSV              Output results to CSV file at this PATH.
  -json JSON            Output results to JSON file at this PATH
  -init-key INIT_KEY    Install your Nu_I.D. API key to the current users
                        PATH.
  -c, -check           Check against Nu_I.D. API for compromised
                        credentials.
  -snap                 Use ntdsutil.exe to snapshot the system registry
                        hive and ntds.dit file to <systemDrive>:\NuID\
  -shred                When performing delete operations on files, use a 7
                        pass overwrite with sdelete.exe. Download here:
                        https://docs.microsoft.com/en-
                        us/sysinternals/downloads/sdelete
  -no-backup            Do not backup the existing snapshots, just overwrite
                        them instead.
  -clean-old-snaps CLEAN_OLD_SNAPS
                        Clean backups older than N days.

display options:
  -user-status          Display whether or not the user is disabled
  -pwd-last-set         Shows pwdLastSet attribute for each account found
                        within the NTDS.DIT database.
  -history              Dump NTLM hash history of the users.
  -v                    Enable verbose mode.

```

#### -snap

The `-snap` param will automatically snapshot Active Directory (using `ntdsutil.exe`), and dump the ntds.dit file as well as the SYSTEM registry hive, if you have the privledges.
You can dump this manually using any variety of methods or the `ntdsutil.exe` tool. 

If dumping manually you can point to the files with `-system path\to\SYSTEM` and `-ntds path\to\ntds.dit`. This is useful if you want to audit old snapshots. 

#### -check

This requires an API key from https://nebulous.nuid.io/#/register. Once you have that and installed with `-init-key`, you can check the hashes against the NuID API.
If you have specified `-history` it will also check each accounts password history to see if there was a password the user previously used that was compromised.

#### -user-status

Adds output indicating whether or not the account is Enabled or Disabled in Active Directory

#### -pwd-last-set

Adds output indicating the date the account's password was last set. 
This can be useful in detecting violations of security policy of accounts that do not get reset automatically as defined in GPO, such as Service Accounts.

#### -history

Also audit or dump the accounts stored password history

#### -shred

Use a DoD 7 pass overwrite when wiping snapshots. This requires having sdelete.exe in your path. You can get that here:
https://docs.microsoft.com/en-us/sysinternals/downloads/sdelete

Just download that and place it in your `%SYSTEMDRIVE\Windows\System32\` directory, or setup the environment variable. 

#### -clean-old-snaps

Useful on cleaning backups when setting this application to run with the Task Scheduler. The SYSTEM hive and .dit file can be rather large in bigger domains and take a good amount of disk space. 
If you use Task Scheduler to make a daily audit, you can use this option like so: `-clean-old-snaps 7` to only store 1 weeks worth of snapshots.

#### -no-backup

If we detect an old snapshot, we back it up to `%SYSTEMDRIVE%\Program Files\NuID\snapshot-backups` by default.
This is due to ntdsutil.exe requiring an empty directory. 
If you want to disable this backup and just wipe the current snapshot, use this argument.

## Known issues

There seems to be a bug in impacket that doesn't allow the nthash to be extracted correctly.
Avoid using the `-history` argument for now.

https://github.com/SecureAuthCorp/impacket/issues/395
https://github.com/SecureAuthCorp/impacket/issues/660