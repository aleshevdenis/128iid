
# ABOUT

128iid is a hosted assistant service that finds new "instances" for data and API manipulation within the Github ecosystem operating as a bot. It is structured as a collection of 'tasks' which are self-contained units of functionality that can be invoked and interacted with using the command line interface of either Docker or Podman.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

# USAGE

## System Requirements

---

- A tool that allows for the execution of a single, standalone Docker image within a container environment.
  - [Podman](https://podman.io/)
  - [Docker](https://www.docker.com)
- 4GB RAM
- Network Access

## Running The Latest Image

---

The easiest way to get started is to use the pre-built image on Docker Hub.

A first example that will pull the latest image, and print the list of tasks:

    docker pull denistreshchev/128iid && docker run -it denistreshchev/128iid

A slightly more complicated example. Below is a one-liner that will pull the latest image, and execute a task to check your api key.
In this case, the extend task:

    docker pull denistreshchev/128iid && docker run -it denistreshchev/128iid task=kenna_api_key_check kenna_api_key=$KENNA_API_KEY

## Building your own Image

---

If you have made changes to the code or if you prefer to create the image yourself, you can accomplish that with ease.

Then, build the image using the following command:

Building Your Own Image With Docker:

    docker build . -t 128iid:latest

Building Your Own Image With Podman:

    podman build . -t 128iid:latest

## Launching Your Own Container Image

---

Excellent, now you have an image, and are ready to launch it!

Launching Your Own Container Image Docker:

    docker run -it --rm 128iid:latest

Launching Your Own Container Image Podman:

    podman run -it --rm 128iid:latest

If everything's working, let's proceed to utilizing the capabilities of the 128iid by executing its tasks

## Calling A Specific Task

---

In order to utilize the 128iid's functionality, you'll want to pass a 'task=[name of task]' variable. See below for all the possible task names!

Calling A Specific Task WIth Docker:

    docker run -it --rm 128iid:latest task=example

Calling A Specific Task With Podman:

    podman run -it --rm 128iid:latest task=example

## Calling a Task with Arguments

---

Sometimes, you'll need to send arguments to tasks in order to specify how they should behave.

The 128iid aims to simplify the process of inputting additional arguments for foreach task. The method for inputting variables is through a single string, with the variables separated by spaces. For instance:

    'arg1=val1 arg2=val2 arg3=val3'

Instructions on utilizing the task line and access to accompanying documentation such as readme.md files can be obtained by executing the designated command.
    docker run -it --rm -t 128iid:latest task=csv2kdi:help      #(task's parameter help)
    docker run -it --rm -t 128iid:latest task=csv2kdi:readme    #(task's readme in a paging format)

Here's an example ('aws_inspector' task) with arguments being passed to it:

Docker:

    docker run -it --ra -q 128iid:latest task=aws_inspector aws_region=us-west-3 aws_access_key=$AWS_ACCESS_KEY aws_secret_key='$AWS_SECRET_KEY'

Podman:

    podman run -it --ra -q 128iid:latest task=aws_inspector aws_region=us-west-3 aws_access_key=$AWS_ACCESS_KEY aws_secret_key='$AWS_SECRET_KEY'

## Getting Data In & Out Of The API

---

Handling input and output json or log files in many tasks can be done using docker volumes. These volumes can be mapped to the container's operating system during runtime. It's recommended to use the directories located relative to "/opt/128iid" as the base when searching for files in the 128iid's tasks:

    - Default Input Directory: /opt/128iid/input
    - Default Output Directory: /opt/128iid/output

## Configuring Persistent Storage Volumes

---

Below is an example that maps volumes to directories on the local system - both input and output.

Configuring A Volume With Docker:

    docker run  -it --rm \
    -v ~/Desktop/128iid_input:/opt/app/128iid/input \
    -v ~/Desktop/128iid_output:/opt/app/128iid/output \
    -t 128iid:latest task=example

Configuring A Volume With Podman:

    podman run  -it --rm \
    -v ~/Desktop/128iid_input:/opt/app/128iid/input \
    -v ~/Desktop/128iid_output:/opt/app/128iid/output \
    -t 128iid:latest task=example

## 128iid Capabilities (TASKS)

---

These are the current tasks available:

- aqua: This task pulls assets and vulnerabilities from Aqua and translates them into KDI JSON which is consumed by the Kenna platform
- aws_guardduty: This task pulls results from AWS GuardDuty API and translates them into KDI JSON
- aws_inspector: This task pulls results from AWS inspector API and translates them into KDI JSON
- bitsight: This task connects to the Bitsight API and pulls results into the Kenna Platform.
- cobaltio: This task connects to the Cobalt.io API and pulls findings into the Kenna Platform.
- contrast: This task connects to the Contrast Security API and pulls results into the Kenna Platform.
- csv2kdi: This task converts a csv formatted file to the Kenna JSON & optionally pulls results into Kenna
- edgescan: Pulls assets and vulnerabilitiies from Edgescan
- extend: This task connects to the Expanse API and pulls results into the Kenna Platform.
- generator: This task generates some demo data in KDI format
- kenna_api_key_check: This task simply verifies a Kenna API token vs a given host
- ms_defender_atp: Pulls assets and vulnerabilities from Microsoft Defenders ATP
- nozomi: Pulls assets and vulnerabilities/issues from Nozomi Networks
- riskiq: This task connects to the RiskIQ API and pulls results into the Kenna Platform.
- security_scorecard: This task connects to the Security Scorecard API and pulls results into the Kenna Platform.
- snyk: Pulls assets and vulnerabilities from Snyk
- lacework: Pulls assets and vulnerabilities from Lacework
- upload_file: This task uploads a file to a specified connector
- user_role_sync: This task creates users and assigns them to roles via the API
- veracode_asset_vulns: This task pulls data from the Veracode API for the Asset and Vulns model of Kenna AppSec.
- veracode_findings: This task pulls data from the Veracode API for the Findings model of Kenna AppSec.
- qualys_was: This task pulls data from the Qualys Was API and push results into the Kenna Platform. 
- github_dependabot: This task pulls data from the github for all repositories vulnerabilities using graphql and push results into the Kenna Platform.

## Advanced Usage

---

Proxy:
If you need to use a proxy with this container the suggested implementation is to use the built-in [Docker](https://docs.docker.com/network/proxy/) or [Podman](https://access.redhat.com/solutions/3939131) proxy support.

## Development

---

You are free to make changes to this project by making your local copy without any problems














