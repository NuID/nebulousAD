NebulousAD
=================================
### Quicklinks


* [About](https://github.com/NuID/nebulousAD#about)
* [Future Releases](https://github.com/NuID/nebulousAD#future-releases)
* [Installation](https://github.com/NuID/nebulousAD#installation)
* [Usage](https://github.com/NuID/nebulousAD#usage)
* [Nebulous REST API](https://github.com/NuID/nebulousAD#nebulous-rest-api)
* [Known Issues](https://github.com/NuID/nebulousAD#known-issues)

### About

NebulousAD is a tool for auditing Active Directory user passwords against a database of compromised passwords found in data breaches. The tool was made to help Windows system administrators find and, optionally, remediate the use of compromised passwords. This approach is recommended by [NIST 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html#sec5), and can help protect against credential spraying and stuffing attacks.

The Nebulous database current holds over 2.5 billion unique hashes of breached passwords.

NebulousAD uses the k-anonymity model by default to preserve the privacy and security of passwords checked against the API. Only the first five characters of a SHA-2 hash are sent to the API. You can read more about k-anon [here.](https://blog.nuid.io/nebulousad-v1-1-with-k-anonymity/)

The tool was originally released at BSides Las Vegas 2019. A video of the BSides presentation is [here.](https://www.youtube.com/watch?v=xJgUdNfWbE4&trk)

### Future Releases:

Upcoming Features:
- Redact-by-group. Allows you to omit hash checking for members of the specific AD group.

### Installation

Simply download the precompiled release (requires no python interpreter), or build from source:

**This tool requires Python2.7 (for now).**

Run `git clone git@github.com:NuID/nebulousAD.git`

Next, install with `python setup.py install`

Then initialize your key. You can get your key by visiting: https://nebulous.nuid.io/#/register
Once registered, click the button to generate your API key and copy it.

Now you can initialize them like so: `nebulousAD -init-key <api_key>`

You can now run the tool. If it can't find your API key, you may need to restart your terminal session. 
The API key is stored in an environment variable. Logging out and back in also works.

### Usage
An example command to dump all hashes and check them against the API:
`nebulousAD.exe -v -snap --check`

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
  -c, --check           Check against Nu_I.D. API for compromised
                        credentials.
  -dk, --disable-k-anon
                        Disable k-anon hash searches against the API (speeds
                        up the audit).
  -snap                 Use ntdsutil.exe to snapshot the system registry
                        hive and ntds.dit file to <systemDrive>:\Program
                        Files\NuID\
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
#### --disable-k-anon

Disables the k-anonymity hashcheck function. This is useful to speed up the search time, but will result in the full SHA-256(NTLM) hash being sent over to the API. We do not log or store hashes sent to the API.


#### -snap

The `-snap` param will automatically snapshot Active Directory (using `ntdsutil.exe`), and dump the ntds.dit file as well as the SYSTEM registry hive, if you have the privileges.
You can dump this manually using any variety of methods or the `ntdsutil.exe` tool. 

If dumping manually you can point to the files with `-system path\to\SYSTEM` and `-ntds path\to\ntds.dit`. This is useful if you want to audit old snapshots. 

#### --check

This requires an API key from https://nebulous.nuid.io/#/register. Once you have that and installed with `-init-key`, you can check the hashes against the NuID API.
If you have specified `-history` it will also check each accounts password history to see if there was a password the user previously used that was compromised.

#### -user-status

Adds output indicating whether or not the account is Enabled or Disabled in Active Directory.

#### -pwd-last-set

Adds output indicating the date the account's password was last set. 
This can be useful in detecting violations of security policy of accounts that do not get reset automatically as defined in GPO, such as Service Accounts.

#### -history

Also audit or dump the accounts stored password history.

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

# Nebulous REST API
A RESTful web API is provided that will allow users to utilize the NuID API Token, once generated, for your own custom client. This section outlines the proper functionality of the web API, valid requests, error types, and more.

### Response
The basic structure of each response will be identical. Without exception, responses must contain the following three fields: **success**, **data**, and **error**. The first thing to determine upon receiving the response is the **success** value. This will determine if you should continue to handle the **data** object, or handle the **error** object instead. The following examples show generic responses from the server in both a success and failure situation:

#### Success
```
{
    success: True,  // Indicates the request completed successfully
    data: {
        /* value depends on endpoint queried */
    },
    error: {} // Empty 
}
```
#### Failure
```
{
    success: False,  // Indicates the request did not complete successfully
    data: { },  // Empty
    error: {
        "ErrorName": "Helpful description of the error that occurred during the request"
    }
}
```
### Errors
Each error offers insight into what went wrong during the request, allowing the user to make necessary changes.

| Error Name | Description | Status Code |
| ---------- | ----------- | ----------- |
| `ActionExpired` | The action you are trying to invoke has expired and is no longer valid | 401
| `ActionInvalid` | The action you are trying to invoke does not exist | 401
| `AuthFailure` | Invalid user/password combination | 401
| `AuthMissingToken` | No authentication token was provided | 401
| `FieldMissing` | One or more fields is missing from the JSON request |  422
| `HashInvalidLength` | The hash provided and the expected length for the given hash type do not match | 422
| `HashInvalidValue` | Expected hexadecimal hash representation | 422
| `HashInvalidPrefix` | A prefix must have a minimum length of 5 characters | 422
| `HashUnsupported` | The hash type provided is unsupported | 422
| `InvalidJWT` | The JWT provided was invalid | 401
| `InvalidRequest` | The request provided was malformed or missing a JSON payload | 422
| `KeyBadUser` | The API key provided does not match the expected user | 401
| `KeyDisabled` | The API key provided is disabled | 403
| `KeyInvalid` | The API key provided is invalid | 401
| `KeyMissing` | No API key was provided | 401
| `NotFound` | The endpoint you're trying to reach is invalid | 404
| `PasswordIncorrect` | The current password does not match | 401
| `UserDisabled` | The account is currently disabled | 401
| `UserKeyLimit` | You have reached the maximum number of API keys | 403
| `UserNotActivated` | The user account has not yet been activated | 403
| `UserNotFound` | The user account cannot be found | 401

### Supported Hashes
At this time only one `hash_type` is supported. These values (case insensitive) can be used in place of `hash_type`. The size of the hexadecimal string representation of the `hash_value` is also provided. The `hash_prefix` cannot exceed this size:

| Hash | Length |
| ---- | ------ |
NTLMSHA2 | 64

### API Endpoints
The following HTTP header must be provided on all API endpoint requests or an error will be returned:
```
X-NUID-API-KEY:   <Your NuID API Key>
```
Each endpoint begins with the following URL:
```
https://nebulous.nuid.io
```


##### `/api/search/kanon/<hash_type>/<hash_prefix>`
**Method:** GET
**Description:** Query the hash database using an anonymized version of a hash. The full hash can be provided, but alternatively, a partial hash can be used in the form of a prefix that is at least 5 characters in length. All hashes in the *Nebulous* database matching this prefix will be returned without disclosing the exact hash itself.
**Response:**
The response from the following URL: `https://nebulous.nuid.io/api/search/kanon/5f4dcc`
```
{
  "success": true,
  "data": {
    "matches": [
      "5f4dcc3010a3b4ffd56ec97b33a0f837",
      "5f4dcc3b5aa765d61d8327deb882cf99",
      "5f4dcc3b5bef0f9cc4c0f96d758010b8"
    ]
  },
  "error": {}
}
```

##### `/api/search/kanon/<hash_type>`
**Method:** POST
**Post Data:**
```
{
    "prefix": "<Hash Prefix>"
}
```
**Description:** Query the hash database using an anonymized version of a hash. The full hash can be provided, but alternatively, a partial hash can be used in the form of a prefix that is at least 5 characters in length. All hashes in the *Nebulous* database matching this prefix will be returned without disclosing the exact hash itself.
**Response:**
The response from the following URL: `https://nebulous.nuid.io/api/search/kanon` with the data `{"prefix": "5f4dcc"}`
```
{
  "success": true,
  "data": {
    "matches": [
      "5f4dcc3010a3b4ffd56ec97b33a0f837",
      "5f4dcc3b5aa765d61d8327deb882cf99",
      "5f4dcc3b5bef0f9cc4c0f96d758010b8"
    ]
  },
  "error": {}
}
```



## Known issues

There seems to be a bug in impacket that doesn't allow the nthash to be extracted correctly.
Avoid using the `-history` argument for now.

https://github.com/SecureAuthCorp/impacket/issues/395
https://github.com/SecureAuthCorp/impacket/issues/660

## Have an issue?

Contact us at nebulous@nuid.io

