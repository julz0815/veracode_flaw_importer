#!/bin/sh -l

#required parameters
appguid=$1


#optional parameters
scantype=$2
importtype=$3
includeannotations=$4

#inital tasks
chmod 777 /jq-linux64


#
# scantype ( STATIC || MANUAL || DYNAMIC || SCA )
# importtype (cwe || scantype || sandbox || severity || severityhigher || category || latestscan || violates_policy)
# optional ( includeannotations ) 
#

$(echo "http --auth-type veracode_hmac --output findings.json GET https://api.veracode.com/appsec/v2/applications/$appguid/findings/?violates_policy=true&size=500")
findingsnumber=$(cat findings.json | /jq-linux64  -r '._embedded.findings' | /jq-linux64 length)
echo "Number of findings found: $findingsnumber"



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
            #echo "Finding #$i"
            #echo $(cat findings.json | /jq-linux64 ._embedded.findings[$i])
            #echo "\\n\\n"
            
          
            
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
            description=$(cat findings.json | /jq-linux64 ._embedded.findings[$i].description| sed 's/"//g' | sed -e 's/<[^>]*>//g')
            severity=$(cat findings.json | /jq-linux64 ._embedded.findings[$i].finding_details.severity| sed 's/"//g')
            filepath=$(cat findings.json | /jq-linux64 ._embedded.findings[$i].finding_details.file_path| sed 's/"//g')
            modulename=$(cat findings.json | /jq-linux64 ._embedded.findings[$i].finding_details.module| sed 's/"//g')
            procedure=$(cat findings.json | /jq-linux64 ._embedded.findings[$i].finding_details.procedure| sed 's/"//g')
            lineofcode=$(cat findings.json | /jq-linux64 ._embedded.findings[$i].finding_details.file_line_numbern| sed 's/"//g')

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
                            \"level\": \"$severity\"
                        },
                        \"properties\": {
                            \"category\": \"CWE: $cwe $cwename\",
                            \"tags\": [
                            \"CWE: $cwe $cwename\"
                            ]
                        }
                    }
            " >> rules.json


            #if more rules add ,
            if [  $i -lt $findingsnumber ]
            then
                echo "
                ," >> rules.json
            else
                echo "
                    ]
                }
            },"
            fi

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
                  \"uri\": \"$modulename - $filepath - $procedure\",
                  \"uriBaseId\": \"%SRCROOT%\"
                },
                \"region\": {
                  \"startLine\": $lineofcode
                }
              }
            }
          ]
        }" >> results.json
            
            #if more results add ,
            if [  $i -lt $findingsnumber ]
            then
                echo "," >> results.json
            else
                echo ""
            fi
    let i=i+1 
done



#create full file
cat sarif.json > fullResults.json
cat rules.json >> fullResults.json
echo "      "results": [" >> fullResults.json
cat results.json >> fullResults.json
#close runs tag
echo "
    }
  ]
}" >> fullResults.json

cat fullResults.json
