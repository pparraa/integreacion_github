#!/bin/bash

lines=$(.github/files/jq-linux64 ' .results.TestResults.Issues.Issue[].Title' .github/files/results.json | wc -l);
i=0;

touch veracode-sarif.json;

echo '
{
    "$schema" : "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    "version" : "2.1.0",
    "runs" :
    [
    {
' >> veracode-sarif.json;

while [ $i != $lines ] ; 
do
    # strting the results array
    echo '
        "tool" : {
            "driver" : {
                "name" : "Veracode Pipeline Scanner"
            }
        },
        "results" : [ {' >> veracode-sarif.json;
    # strting the results array

    # starting the message tag
    title=$(.github/files/jq-linux64 ' .results.TestResults.Issues.Issue['$i'].Title' .github/files/results.json | sed 's/"//g');
    issuetype=$(.github/files/jq-linux64 ' .results.TestResults.Issues.Issue['$i'].IssueType' .github/files/results.json | sed 's/"//g');
    #echo $title;
    echo '
            "message" : {
                "text" : "'$title' - '$issuetype'"
            },
        ' >> veracode-sarif.json;
    # ending the message tag

    #starting locations tag

    echo '
         "locations" : [ ' >> veracode-sarif.json;

    file=$(.github/files/jq-linux64 ' .results.TestResults.Issues.Issue['$i'].Files.SourceFile.File' .github/files/results.json | sed 's/"//g');
    line=$(.github/files/jq-linux64 ' .results.TestResults.Issues.Issue['$i'].Files.SourceFile.Line' .github/files/results.json | sed 's/"//g');
    function=$(.github/files/jq-linux64 ' .results.TestResults.Issues.Issue['$i'].Files.SourceFile.FunctionName' .github/files/results.json | sed 's/"//g');
    echo '
            {
                "physicalLocation" : {
                    "artifactLocation" : {
                        "uri" : "File: '$file' - Line: '$line' - Function: '$function'"
                    },
    ' >> veracode-sarif.json

    echo '
                    "region" : {
                            "startLine" : '$line',
                            "startColumn" : 0,
                            "endColumn" : 0
                        }
                }
            }],
    ' >> veracode-sarif.json
    #ending locations tag


    #start hash
    echo '
            
            "partialFingerprints" : {
                "primaryLocationLineHash" : "NULL"
            }' >> veracode-sarif.json      
    #ending hash
    
    #ending the results array
    echo '
        }]
    }' >> veracode-sarif.json;

 i=$[$i+1];

    if [ $i != $lines ];
    then
    echo '
    ,{' >> veracode-sarif.json;
    fi
    #ending the results array

   

done

echo '
    ]
}
' >> veracode-sarif.json;