# veracode_flaw_importer
Import Veracode static analysis findings to Github Security "Code Scanning Alerts"

# Required paramters
### `app_name`
**Required:** The name of the application
### OR
### `app_guid`
**Required:** The GUID of the application, can be found via API calls

**EITHER THE app_name OR THE app_guid PARAMETER NEED TO BE PROVIDED**

# Optional paramters
### `sandbox_name`
**Optional:** The name of the sandbox
### `sandbox_guid`
**Optional:** The GUID of the sandbox, can be found via API calls

# Description
The Veracode Flaw Importer will only import static analysis findings of the last scan with the provided information. Either from a policy scan or from a sandbox scan.
Please be aware that the scan first has to finish before the results can be imported
If you are using this flaw importer with in you pipeline, make sure the previous task, most probably the Veracode action **uploadandscan**, is using the **scantimeout** option to wait for the scan to finish before you import the flaws.

## Example usage

The following example will import flaws from an application profile called "Verademo" and a corresponding sandbox called "Feature ABC"

The Veracode credentials are read from github secrets. NEVER STORE YOUR SECRETS IN THE REPOSITORY.

```yaml
    # Checks-out your repository under $GITHUB_WORKSPACE, so your job can access it
    - uses: actions/checkout@v2
    - name: Getflaws
      uses: ./ # Uses an action in the root directory
      env: 
        VERACODE_API_KEY_ID: '${{ secrets.VERACODE_API_ID }}'
        VERACODE_API_KEY_SECRET: '${{ secrets.VERACODE_API_KEY }}'
      id: get_flaws  
      with:
        app_name: 'Verademo'
        sandbox_name: 'Feature ABC'
```
