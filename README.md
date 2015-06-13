# ThreatSpec

__An experiment in agile threat modelling__

Traditional software threat modelling can take various forms, but a common approach for software security is to look at the components involved in the application stack, define trust boundaries, and to look at threats and mitigations of those components and how they interact with eachother. Ideally this threat modelling is done before any code is written, and requires architects, developers, operations and security to work together to define the software model and to identify threats. They will typically create a large diagram of how the components relate, systematically work through the treats and track any identified treats using some sort of ticketing system.

Unfortunately, this approach is more suited to the waterfall development methodology than anything agile. These days, agile organisations often start coding minimum viable products (MVP) to test out an idea. At this stage they might not what exactly which components are required or how they relate, making traditional threat modelling particularly difficult.

This tool turns threat modelling on its head, and attempts to tighten the feedback loop between development and security. 

When a developer writes a new function, no matter how simple, they use comments to bring that function into a threat model context at the same time as they write the code and documentation comments. The developers can start to define mitigations and exposures immediately, and during code review other developers or security engineers can pitch in with suggestions. As the code is written, developers and security engineers can use the ThreatSpec tool to generate an overview report, including a data flow diagram, to identify areas of concern. This is then fed back to the developers and the cycle continues.

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

## Usage

## Tutorial


## Contributing
