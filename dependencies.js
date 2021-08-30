/*
command args
1 - Gitlab Private token
2 - Issue generation true|false
3 - Gitlab project ID - integer
4 - create a new issue if the previous is in stat closed, but the issue still shows up from the scan true|false
*/

const fs = require('fs');
const Axios = require('axios');
const Math = require('mathjs');

const scaInputFileName = 'scaResults.json'; // 'results.json'
const GitlabOutputFileName = 'output-sca-vulnerabilites.json'; // 'veracode-results.json'
var vulns=[];
var vulnerabilities=[];
var remeds=[];
var remediations=[];
var mapSeverity = "";

var myArgs = process.argv.slice(2);



const convertSCAResultFileToJSONReport = async(inputFileName,outputFileName) => {
    var results = {};
    var vulnResults={};
    var listIssueResponse={};

    var rawdata = fs.readFileSync(inputFileName);
    results = JSON.parse(rawdata);
    console.log('SCA Scan results file found and parsed - validated JSON file');

    var issues = results.records[0].vulnerabilities;
    numberOfVulns = issues.length
    console.log('Vulnerabilities count: '+issues.length);


    // check for existing issue and store results in listIssueResponse
    if (myArgs[1] == 'true'){        
        try {
          var listIssueResponse = await Axios.request({
            method: 'GET',
            headers:{
                'PRIVATE-TOKEN': myArgs[0]
            },
            url: 'https://gitlab.com/api/v4/projects/'+myArgs[2]+'/issues?per_page=100&lables=Dependency%21Scanning'
          });
          console.log('Exisiting issues found')
        }
        catch (e) {
          console.log(e)
        }
    }



        // Report JSON creation
        var i = 0;
        while (i < numberOfVulns) {
            var  refLink = results.records[0].vulnerabilities[i].libraries[0]._links.ref;
            var libRef = refLink.split("/");

            var oldSeverity = parseInt(results.records[0].vulnerabilities[i].cvssScore);

            //severity mapping
            if (oldSeverity == '0.0')
              mapSeverity = 'Unknown'
            else if (oldSeverity >= '0.1' && oldSeverity < '3.9')
              mapSeverity = 'Low'
            else if (oldSeverity >= '4.0' && oldSeverity < '6.9')
              mapSeverity = 'Medium'
            else if (oldSeverity >= '7.0' && oldSeverity < '8.9')
              mapSeverity = 'High'
            else if (oldSeverity >= '9.0')
              mapSeverity = 'Critical'

            // construct Vulnerabilities for reports file
            vulns = {
                id: results.records[0].libraries[libRef[4]].versions[0].sha1,
                category: "dependency_scanning",
                name: results.records[0].vulnerabilities[i].title+' at '+results.records[0].libraries[libRef[4]].name,
                message: '',
                description: results.records[0].libraries[libRef[4]].description+' - '+results.records[0].vulnerabilities[i].overview,
                severity: mapSeverity,
                solution: results.records[0].vulnerabilities[i].libraries[0].details[0].fixText,
                scanner: {
                    id: "Veracode Agent Based SCA",
                    name: "Veracode Agent Based SCA"
                  },
                  location: {
                    file: "",
                    dependency: {
                      package: {
                        name: results.records[0].libraries[libRef[4]].coordinateType+':'+results.records[0].libraries[libRef[4]].coordinate1+':'+results.records[0].libraries[libRef[4]].coordinate2,
                      },
                      version: results.records[0].libraries[libRef[4]].versions[0].version
                    }
                  },
                  identifiers: [
                    {
                      type: "Veracode Agent Based SCA",
                      name: results.records[0].vulnerabilities[i].language+' - '+results.records[0].libraries[libRef[4]].name+' - Version: '+results.records[0].vulnerabilities[i].libraries[0].details[0].versionRange+' - CVE: '+results.records[0].vulnerabilities[i].cve,
                      value: results.records[0].vulnerabilities[i].language+' - '+results.records[0].libraries[libRef[4]].name+' - Version: '+results.records[0].vulnerabilities[i].libraries[0].details[0].versionRange+' - CVE: '+results.records[0].vulnerabilities[i].cve,
                      url: results.records[0].libraries[libRef[4]].bugTrackerUrl
                    }
                  ],
                  links: [
                    {
                      url: results.records[0].libraries[libRef[4]].versions[0]._links.html
                    },
                    {
                      url: results.records[0].vulnerabilities[i]._links.html
                    },
                    {
                      url: results.records[0].vulnerabilities[i].libraries[0].details[0].patch
                    }
                  ]
            };

            remeds = {
                              fixes: 
                              [
                                {
                                  id: results.records[0].libraries[libRef[4]].versions[0].sha1
                                }
                              ],
                              summary: results.records[0].vulnerabilities[i].libraries[0].details[0].fixText,
                              diff: ""
                            };
            
            vulnerabilities.push(JSON.stringify(vulns));
            remediations.push(JSON.stringify(remeds));


            //issue section
            if (myArgs[1] == 'true'){

              // set a few vars
              var weight = Math.floor(results.records[0].vulnerabilities[i].cvssScore);

              // map CVSS to severity lable
              /*
              0 - Informational
              0.1 - 2 - Very Low
              2.1 - 4 - Low
              4.1 - 6 - Medium
              6.1 - 8 - High
              8.1 - 10 - Very High
              */

              if (weight == '0.0')
                  severityLabel = 'Informational'
              else if (weight >= '0.1' && weight < '1.9')
                  severityLabel = 'Very Low'
              else if (weight >= '2.0' && weight < '3.9')
                  severityLabel = 'Low'
              else if (weight >= '4.0' && weight < '5.9')
                  severityLabel = 'Medium'
              else if (weight >= '6.0' && weight < '7.9')
                  severityLabel = 'High'
              else if (weight >= '8.0')
                  severityLabel = 'Very High'


              if (results.records[0].vulnerabilities[i].cve == null){
                myCVE = '0000-0000';
              }
              else {
                myCVE = results.records[0].vulnerabilities[i].cve;
              }

              var title = "Dependency Issue - "+results.records[0].vulnerabilities[i].language+" - "+results.records[0].libraries[libRef[4]].name+" - Version: "+results.records[0].vulnerabilities[i].libraries[0].details[0].versionRange+" - CVE: "+myCVE;
              var label = "Dependency Scanning,"+myCVE+","+severityLabel;
              var description = "Software Composition Analysis  \n  \n  \nLanguage: "+results.records[0].vulnerabilities[i].language+"  \nLibrary: "+results.records[0].libraries[libRef[4]].name+"  \nCVE: "+results.records[0].vulnerabilities[i].cve+"  \nVersion: "+results.records[0].vulnerabilities[i].libraries[0].details[0].versionRange+"  \nDescription: "+results.records[0].libraries[libRef[4]].description+"  \n"+results.records[0].vulnerabilities[i].overview+"  \nFix: "+results.records[0].vulnerabilities[i].libraries[0].details[0].fixText+"  \nLinks: "+results.records[0].libraries[libRef[4]].versions[0]._links.html+"  \n"+results.records[0].vulnerabilities[i]._links.html+"  \n"+results.records[0].vulnerabilities[i].libraries[0].details[0].patch;

              // check for dublicated issues
              var existingIssues = listIssueResponse.data;
              numberOfExisingIssues = existingIssues.length
              
              j = 0;
              var exisitingFininding = false;
              while (j < numberOfExisingIssues){
                //console.log(existingIssues[j].title+" - "+title+"\n"+existingIssues[j].weight+" - "+weight+"\n"+existingIssues[j].labels[0]+" - "+myCVE)
                if (existingIssues[j].title == title && existingIssues[j].weight == weight && existingIssues[j].labels[0] == myCVE){
                  if(myArgs[3] == 'true'){
                    if(existingIssues[j].state == "closed"){
                      exisitingFininding = false;
                    }
                    else{
                      exisitingFininding = true;
                    }
                  }
                  else {
                    exisitingFininding = true;              
                  }
                }
              j++;
              }

              if (exisitingFininding != true){
                console.log("Issue needs to be created - "+title)

                  // create new issue
                  try {
                    var data = JSON.stringify({
                      title: title,
                      labels: label,
                      description: description,
                      weight: weight
                    })

                    var createIssueResposne = await Axios.request({
                      method: 'POST',
                      headers:{
                          'Content-Type': 'application/json',
                          'PRIVATE-TOKEN': myArgs[0]
                      },
                      data,
                      url: 'https://gitlab.com/api/v4/projects/'+myArgs[2]+'/issues'
                    });
                  }
                  catch (e) {
                    console.log(e)
                    console.log(e.response.data)
                  }

              }
              else {
                console.log('Issue already exists '+title)
              }
            }
            i++;
        }
        //vulns & remediations start
        var vulnsStart = '{"version": "2.0","vulnerabilities":[';
        var remediationsStart = '"remediations": [';
        // vulns & remediations finish
        var vulnsEnd = ']';
        var remediationsEnd = ']}';
        //create full report
        var fullReportString = vulnsStart+vulnerabilities+vulnsEnd+','+remediationsStart+remediations+remediationsEnd
        var vulnerabilitiesReport = JSON.parse(fullReportString);
        //console.log('Vulnerabilities:'+fullReportString);


        // save to file
        fs.writeFileSync(outputFileName,fullReportString);
        console.log('Report file created: '+outputFileName);
}





//try {
    convertSCAResultFileToJSONReport(scaInputFileName,GitlabOutputFileName);
//} 
//catch (error) {
//    core.setFailed(error.message);
//}

module.exports = {
    converSCAResulst: convertSCAResultFileToJSONReport,
}
