#!/bin/sh -l

#required parameters
appname=$(echo "$1" | sed -e 's/%/%25/g' -e 's/ /%20/g' -e 's/!/%21/g' -e 's/"/%22/g' -e 's/#/%23/g' -e 's/\$/%24/g' -e 's/\&/%26/g' -e 's/'\''/%27/g' -e 's/(/%28/g' -e 's/)/%29/g' -e 's/\*/%2a/g' -e 's/+/%2b/g' -e 's/,/%2c/g' -e 's/-/%2d/g' -e 's/\./%2e/g' -e 's/\//%2f/g' -e 's/:/%3a/g' -e 's/;/%3b/g' -e 's//%3e/g' -e 's/?/%3f/g' -e 's/@/%40/g' -e 's/\[/%5b/g' -e 's/\\/%5c/g' -e 's/\]/%5d/g' -e 's/\^/%5e/g' -e 's/_/%5f/g' -e 's/`/%60/g' -e 's/{/%7b/g' -e 's/|/%7c/g' -e 's/}/%7d/g' -e 's/~/%7e/g')
appname_raw=$1
appguid=$2
sandboxname=$(echo "$3" | sed -e 's/%/%25/g' -e 's/ /%20/g' -e 's/!/%21/g' -e 's/"/%22/g' -e 's/#/%23/g' -e 's/\$/%24/g' -e 's/\&/%26/g' -e 's/'\''/%27/g' -e 's/(/%28/g' -e 's/)/%29/g' -e 's/\*/%2a/g' -e 's/+/%2b/g' -e 's/,/%2c/g' -e 's/-/%2d/g' -e 's/\./%2e/g' -e 's/\//%2f/g' -e 's/:/%3a/g' -e 's/;/%3b/g' -e 's//%3e/g' -e 's/?/%3f/g' -e 's/@/%40/g' -e 's/\[/%5b/g' -e 's/\\/%5c/g' -e 's/\]/%5d/g' -e 's/\^/%5e/g' -e 's/_/%5f/g' -e 's/`/%60/g' -e 's/{/%7b/g' -e 's/|/%7c/g' -e 's/}/%7d/g' -e 's/~/%7e/g')
sandboxname_raw=$3
sandboxguid=$4

#optional parameters
scantype=$4
includeannotations=$5

#inital tasks
chmod 777 /jq-linux64

if [ -z $appguid ]
then
  if [ -z $appname ]
  then
    echo "ERRO: either app-name or app-guid need to be set"
    exit 1
  else
    echo "Searching app: \"$appname_raw\""
    $(echo "http --auth-type veracode_hmac --output apps.json GET https://api.veracode.com/appsec/v1/applications?name=$appname")
    appsnumber=$(cat apps.json | /jq-linux64  -r '._embedded.applications' | /jq-linux64 length)
    echo "$appsnumber apps found"
    j=0
    while [  $j -lt $appsnumber ]; do
      let $appsnumber-1
      appfindingsname=$(cat apps.json | /jq-linux64 ._embedded.applications[$j].profile.name | sed 's/"//g')
      echo "app $j: $appfindingsname"
      if [ "$appname_raw" = "$appfindingsname" ]
      then
        appguid=$(cat apps.json | /jq-linux64 ._embedded.applications[$j].guid | sed 's/"//g')
        echo "App $appname_raw found: 
  - App GUID: $appguid"
      fi
      let j=j+1 
    done
    if [ -z $appguid ]
    then
      echo "ERROR: no app guid found!"
      exit 1
    fi
  fi
fi

echo "
"

if [ -z $sandboxguid ] && [ -z $sandboxname ]
then
  echo "Not a sandbox scan"
else
  if [ -z $sandboxguid ]
  then
    echo "Searching sandbox: \"$sandboxname_raw\""
    $(echo "http --auth-type veracode_hmac --output sandboxes.json GET https://api.veracode.com/appsec/v1/applications/$appguid/sandboxes")
    sandboxnumber=$(cat sandboxes.json | /jq-linux64  -r '._embedded.sandboxes' | /jq-linux64 length)
    echo "$sandboxnumber sandboxes found"
    k=0
    while [  $k -lt $sandboxnumber ]; do
      let $sandboxnumber-1
      sandboxfindingsname=$(cat sandboxes.json | /jq-linux64 ._embedded.sandboxes[$k].name | sed 's/"//g')
      echo "sandbox $k: $sandboxfindingsname"
      if [ "$sandboxname_raw" = "$sandboxfindingsname" ]
      then
        sandboxguid=$(cat sandboxes.json | /jq-linux64 ._embedded.sandboxes[$k].guid | sed 's/"//g')
        echo "Sandbox $sandboxname_raw found: 
  - Sandbox GUID: $sandboxguid"
      fi
      let k=k+1 
    done
    if [ -z $sandboxguid ]
    then
      echo "ERROR: no sandbox guid found!"
      exit 1
    else
      sandboxguid=$sandboxguid
    fi
  fi
fi

echo "
Get static flaws
"

if [ -z $sandboxguid ]
then
  $(echo "http --auth-type veracode_hmac --output findings.json GET https://api.veracode.com/appsec/v2/applications/$appguid/findings/?violates_policy=true&size=500&scantype=STATIC")
else
  $(echo "http --auth-type veracode_hmac --output findings.json GET https://api.veracode.com/appsec/v2/applications/$appguid/findings/?violates_policy=true&size=500&scantype=STATIC&context=$sandboxguid")
fi
findingsnumber=$(cat findings.json | /jq-linux64  -r '._embedded.findings' | /jq-linux64 length)
echo "Found: $findingsnumber findings"


#Start construct SARIF
echo "
{
\"\$schema\" : \"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json\",
\"version\" : \"2.1.0\",
    \"runs\" : [
            {
            \"tool\" : {
                \"driver\" : {
                    \"name\" : \"Veracode Static Analysis Scan\",
                    \"rules\" : [" > sarif.json



i=0
while [  $i -lt $findingsnumber ]; do
            let number=$findingsnumber-1
            open=$(cat findings.json | /jq-linux64 ._embedded.findings[$i].finding_status.status | sed 's/"//g')
            
            if [[ "$open" == "OPEN" || "$open" == "REOPENED" ]]
            then
          
            
            #Add rules
#            {
#              "id": "3f292041e51d22005ce48f39df3585d44ce1b0ad",
#              "name": "js/unused-local-variable",
#              "shortDescription": {
#                "text": "Unused variable, import, function or class"
#              },
#              "fullDescription": {
#                "text": "Unused variables, imports, functions or classes may be a symptom of a bug and should be examined carefully."
#              },
#              "defaultConfiguration": {
#                "level": "note"
#              },
#              "properties": {
#                "tags": [
#                  "maintainability"
#                ],
#                "precision": "very-high"
#              }

            cwe=$(cat findings.json | /jq-linux64 ._embedded.findings[$i].finding_details.cwe.id | sed 's/"//g')
            cwename=$(cat findings.json | /jq-linux64 ._embedded.findings[$i].finding_details.cwe.name| sed 's/"//g')
            guid=$(cat findings.json | /jq-linux64 ._embedded.findings[$i].context_guid| sed 's/"//g')
            issueid=$(cat findings.json | /jq-linux64 ._embedded.findings[$i].issue_id| sed 's/"//g')
            description=$(cat findings.json | /jq-linux64 ._embedded.findings[$i].description| sed 's/"//g' | sed -e 's/<[^>]*>//g' | sed 's/\\//g')
            severity=$(cat findings.json | /jq-linux64 ._embedded.findings[$i].finding_details.severity| sed 's/"//g')
            filepath=$(cat findings.json | /jq-linux64 ._embedded.findings[$i].finding_details.file_path| sed 's/"//g')
            filename=$(cat findings.json | /jq-linux64 ._embedded.findings[$i].finding_details.file_name| sed 's/"//g')
            modulename=$(cat findings.json | /jq-linux64 ._embedded.findings[$i].finding_details.module| sed 's/"//g')
            procedure=$(cat findings.json | /jq-linux64 ._embedded.findings[$i].finding_details.procedure| sed 's/"//g')
            lineofcode=$(cat findings.json | /jq-linux64 ._embedded.findings[$i].finding_details.file_line_number| sed 's/"//g')
            
            
            echo "File Name: $filename"
            echo "Folder: " pwd
            find ~ -name $filename

            echo "
                    {
                        \"id\": \"$guid - $issueid\",
                        \"name\": \"CWE: $cwe $cwename\",
                        \"shortDescription\": {
                            \"text\": \"$cwename\"
                        },
                        \"fullDescription\": {
                            \"text\": \"$description\"
                        },
                        \"helpUri\": \"https://cwe.mitre.org/data/definitions/$cwe.html\",
                        \"defaultConfiguration\": {
                            \"level\": \"error\"
                        },
                        \"properties\": {
                            \"category\": \"CWE: $cwe $cwename\",
                            \"tags\": [
                            \"CWE: $cwe $cwename\",
                            \"module: $modulename\",
                            \"filepath: $filepath\",
                            \"function: $procedure\"
                            ]
                        }
                    }
            " >> rules.json

            #Add results
#        {
#          "ruleId": "3f292041e51d22005ce48f39df3585d44ce1b0ad",
#          "ruleIndex": 0,
#          "message": {
#            "text": "Unused variable foo."
#          },
#          "locations": [
#            {
#              "physicalLocation": {
#                "artifactLocation": {
#                  "uri": "main.js",
#                  "uriBaseId": "%SRCROOT%"
#                },
#                "region": {
#                  "startLine": 2,
#                  "startColumn": 7,
#                  "endColumn": 10
#                }
#              }
#            }
#          ],
#          "partialFingerprints": {
#            "primaryLocationLineHash": "39fa2ee980eb94b0:1",
#            "primaryLocationStartColumnFingerprint": "4"
#          }
#        }

            echo "
        {
          \"ruleId\": \"$guid - $issueid\",
          \"ruleIndex\": $i,
          \"message\": {
            \"text\": \"$cwename\"
          },
          \"locations\": [
            {
              \"physicalLocation\": {
                \"artifactLocation\": {
                  \"uri\": \"$filepath\",
                  \"uriBaseId\": \"%SRCROOT%\"
                },
                \"region\": {
                  \"startLine\": $lineofcode
                }
              }
            }
          ]
        }" >> results.json
          
        #if more rules/results, add a ","
        let second_last=$number-1
        if [  $i -lt $second_last ]
        then
          echo "
          ," >> rules.json
          echo "," >> results.json
        elif [ $i -eq $second_last ]
        then
          open_last=$(cat findings.json | /jq-linux64 ._embedded.findings[$number].finding_status.status | sed 's/"//g')
          if [[ "$open_last" == "OPEN" || "$open_last" == "REOPENED" ]]
          then
            echo "
            ," >> rules.json
            echo "," >> results.json
          fi
        fi
          
    else
      echo "Finding #$i is a closed/mitigated finding and will not be imported"
    fi
    
    #if no more rules/results, close tag
    if [  $i -eq $number ]
    then
      echo "
          ]
        }
      }," >> rules.json
      echo "
          ]" >> results.json
    fi
    
    
    let i=i+1 
done



#create full file
cat sarif.json > fullResults.json
cat rules.json >> fullResults.json
echo "    \"results\": [" >> fullResults.json
cat results.json >> fullResults.json
#close runs tag
echo "
        }
  ]
}" >> fullResults.json

#cat fullResults.json
