# ThreatSpec

__An experiment in agile threat modelling__

Traditional software threat modelling can take various forms, and a common approach is to look at the components that make up an application stack, define trust boundaries, and to look at threats and mitigations of those components and how they interact with eachother. Typically the threat modelling is done before any code is written, and requires architects, developers, operations and security to work together to define the software model and to identify threats. Together they create a large diagram of how the components relate, and systematically work through the threats and track any identified treats using some sort of ticketing system.

Unfortunately, this approach is more suited to the waterfall development methodology than anything agile. These days, agile organisations often start coding minimum viable products (MVP) to test out an idea. At this stage they might not even know what exactly which components are required or how they relate, making traditional threat modelling particularly difficult.

This tool turns threat modelling on its head, and attempts to tighten the feedback loop between development and security. 

When a developer writes a new function, no matter how simple, they use comments to bring that function into a threat model context at the same time as they write the code and other documentation comments. The developers can start to define mitigations and exposures immediately, and during code review other developers or security engineers can pitch in with suggestions. As the code is written, developers and security engineers can use the ThreatSpec tool to generate an overview report, including a component diagram, to identify areas of concern. This is then fed back to the developers and the cycle continues.

## Example threat model

A function definition (see simple.go)

    // ThreatSpec SimpleV1 for (*main.Page).save
    // Exposes WebApp:FileSystem to arbitrary file writes with insufficient path validation
    // Mitigates WebApp:FileSystem against unauthorised access with strict file permissions
    // Sends notification email from WebApp:App to User:Mail Client

    func (p *Page) save() error {
      filename := p.Title + ".txt"
      return ioutil.WriteFile(filename, p.Body, 0600)
    }

Diagram for simple.go

![Example threat model diagram](https://raw.githubusercontent.com/pki-io/threatspec/master/threatspec.png)

## Caution

This is an experimental tool, so your milage may vary. The limitations are:

* Bugs
* Missing features
* Only works with the Go language for now
* Hacky and ugly code
* Graphs may not scale for big projects
* Specification may change

## Installation

You'll need to have Go's callgraph available somewhere in your $PATH.

Just download threatspec.rb and put it in your $PATH.

## Usage

    callgraph FILES | ./threatspec.rb FILES

For example

    callgraph *.go | ./threatspec.rb *.go

This will write the markdown report to stdout and will create a threatspec.png file.

## Tutorial

You and a colleague have had an interesting idea for a new service and have agreed to spend a week testing out the idea by building an MVP. You arrive at work on Monday morning and your colleague points you to the code she hacked together on the train that morning. It has a few bugs so she asks you to take a look while she finishes off another project. You agree and decide that it would be good to start the threat modelling as early as possible.

You pull down the code (simple.go) and fix the bugs. You then run:

    callgraph *.go | ./threatspec.rb *.go && open threatspec.png

to find an empty png and a nearly empty report:

    # ThreatSpec Report for ...

    # Analysis
    * Functions found: 9
    * Functions covered: 0.0% (0)
    * Functions tested: Infinity% (1)

    # Components

After looking at the code for a few moments, you realise that it would make sense to map out the components first, before trying to add any mitigations, using a combination of "ThreatSpec" and "Does" comments for each of the functions. The comments for save() look like:

    // ThreatSpec SimpleV1 for (*main.Page).save
    // Does page saving for WebApp:FileSystem

    func (p *Page) save() error {
      filename := p.Title + ".txt"
      return ioutil.WriteFile(filename, p.Body, 0600)
    }

After running the command again, things are looking more interesting. The report now has some components:

    # ThreatSpec Report for ...

    # Analysis
    * Functions found: 9
    * Functions covered: 88.89% (8)
    * Functions tested: 12.5% (1)

    # Components
    ## WebApp FileSystem
    ## WebApp App
    ## WebApp Web

And the image is looking better too:

![basic example](https://raw.githubusercontent.com/pki-io/threatspec/master/tutorial/image1.png)

You have a web application, but there is no mention of the user's browser. You fix this by adding a 'Receives' comment to the main() function:

    // ThreatSpec SimpleV1 for main.main
    // Does network listener for WebApp:Web
    // Does request routing for WebApp:Web
    // Receives http from User:Browser to WebApp:Web

    func main() {
    ...

Now you have two trust boundaries and thanks to callgraph a relationship between the components you defined, and even a pretty purple line for the external component:

![example including external component](https://raw.githubusercontent.com/pki-io/threatspec/master/tutorial/image2.png)

You smile to yourself as you decide to put your attacker hat on and work through some of the threats that are exposed. You quickly work through the code, adding "Exposes" comments for whatever comes to mind, for example:

    // ThreatSpec SimpleV1 for main.loadPage
    // Does page loading for WebApp:FileSystem
    // Exposes WebApp:FileSystem to arbitrary file reads with insufficient path validation

    func loadPage(title string) (*Page, error) {
    ...

The report is now looking a lot more interesting:

    # ThreatSpec Report for ...

    # Analysis
    * Functions found: 9
    * Functions covered: 88.89% (8)
    * Functions tested: 12.5% (1)

    # Components
    ## WebApp FileSystem
    ### Threat: arbitrary file writes
    * Exposure: insufficient path validation ((*main.Page).save in simple.go:31)

    ### Threat: arbitrary file reads
    * Exposure: insufficient path validation (main.loadPage in simple.go:40)

    ## WebApp App
    ### Threat: XSS injection
    * Exposure: insufficient input validation (main.editHandler in simple.go:65)

    ### Threat: content injection
    * Exposure: insufficient input validation (main.saveHandler in simple.go:77)

    ## WebApp Web

You also take a look at the diagram notice that it's showing some pretty red colours for your exposures:

![example including exposures](https://raw.githubusercontent.com/pki-io/threatspec/master/tutorial/image3.png)

After adding in some "Mitigates" comments, you see that one of the lines has turned green and one of the red ones has turned orange, representing only mitigations and a combination of mitigations and exposures respectively. The save() function now looks like:

    // ThreatSpec SimpleV1 for (*main.Page).save
    // Does page saving for WebApp:FileSystem
    // Exposes WebApp:FileSystem to arbitrary file writes with insufficient path validation
    // Mitigates WebApp:FileSystem against unauthorised access with strict file permissions

    func (p *Page) save() error {
      filename := p.Title + ".txt"
      return ioutil.WriteFile(filename, p.Body, 0600)
    }


And the diagram has become:

![example including mitigations](https://raw.githubusercontent.com/pki-io/threatspec/master/tutorial/image4.png)

Finally, you get a message from you colleague asking you to add in an email notification option for file changes. You quickly code something and use a "Sends" comment to reflect the activity in your threat model:

![full example](https://raw.githubusercontent.com/pki-io/threatspec/master/tutorial/image5.png)

    # ThreatSpec Report for ...

    # Analysis
    * Functions found: 9
    * Functions covered: 88.89% (8)
    * Functions tested: 12.5% (1)

    # Components
    ## WebApp FileSystem
    ### Threat: unauthorised access
    * Mitigation: strict file permissions ((*main.Page).save in simple.go:33)

    ### Threat: arbitrary file writes
    * Exposure: insufficient path validation ((*main.Page).save in simple.go:33)

    ### Threat: arbitrary file reads
    * Exposure: insufficient path validation (main.loadPage in simple.go:42)

    ## WebApp App
    ### Threat: XSS injection
    * Exposure: insufficient input validation (main.editHandler in simple.go:67)

    ### Threat: content injection
    * Exposure: insufficient input validation (main.saveHandler in simple.go:79)

    ## WebApp Web
    ### Threat: resource access abuse
    * Mitigation: basic input validation (main.makeHandler in simple.go:108)

    ### Threat: privilege escalation
    * Mitigation: non-privileged port (main.main in simple.go:125)

Happy with the progress so far you commit and push your branch for someone to review. You also upload the threat report and diagram, dropping a link in to the WebOps chat room. A few moments later you get an IM from one of the security guys. He loves the threat model and wanted to know how you made it. You explained that it is all code-driven and point him to the branch. He thanks you. After thirty minutes you get another IM from the security guy. He says he's added some comments to your change, so you go to have a look. Tickets created for six new threats. You fire up your IDE and start coding the first mitigation...

## Specification

### ThreatSpec

ThreatSpec MODEL for FUNCTION

Regular expression:

    ^\s*(?:\/\/|\#)\s*ThreatSpec (?<model>.+?) for (?<function>.+?)\s*$

### Mitigation

Mitigates BOUNDARY:COMPONENT against THREAT with MITIGATION (REF)

Regular expression:

    ^\s*(?:\/\/|\#)\s*Mitigates (?<component>.+?) against (?<threat>.+?) with (?<mitigation>.+?)\s*(?:\((?<ref>.*?)\))?\s*$

### Exposure

Exposes BOUNDARY:COMPONENT to THREAT with EXPOSURE (REF)

Regular expression:

    ^\s*(?:\/\/|\#)\s*Exposes (?<component>.+?) to (?<threat>.+?) with (?<exposure>.+?)\s*(?:\((?<ref>.*?)\))?\s*$

### Does action

Does ACTION for BOUNDARY:COMPONENT (REF)

Regular expression:

    ^\s*(?:\/\/|\#)\s*Does (?<action>.+?) for (?<component>.+?)\s*(?:\((?<ref>.*?)\))?\s*$

### Send/receive

Sends/Receives SUBJECT from BOUNDARY:COMPONENT to BOUNDARY:COMPONENT

Regular expression:

    ^\s*(?:\/\/|\#)\s*(?<direction>Sends|Receives) (?<subject>.+?) from (?<from_component>.+?) to (?<to_component>.+?)$

### Test

Tests FUNCTION for THREAT (REF)

Regular expression:

    ^\s*(?:\/\/|\#)\s*Tests (?<function>.+?) for (?<threat>.+?)\s*(?:\((?<ref>.*?)\))?\s*$

## Contributing
