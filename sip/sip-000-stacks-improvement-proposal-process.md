# SIP-000 Stacks Improvement Proposal Process

## Preamble 

Title: Stacks Improvement Proposal Process
Author: Ken Liao <yukanliao@gmail.com>
Status: Draft
Type: Process
Created: 
License: BSD-2-Clause

## Abstract

Stacks improvement proposals (SIP) are documented design proposals aimed at improving the Stacks blockchain. They should contain concise technical specifications of features or standards and the rationale behind it. SIPs are intended to be the primary mechanism of proposing new features, for collecting of community input on an issue and for documenting design decisions.

## Specification

**SIP Workflow & States**

Draft → Proposed → Final/Active → Obsolete
|
|--------------|--------------|
↓              ↓              ↓                 
Deferred    Rejected      Withdrawn

**Draft**
SIP drafts should be submitted as pull requests to the Blockstack core repository. In this state, further changes can be made. Once a member of the core developer committee has reviewed the SIP and determined that there is support in the community, a SIP number will be assigned. You should not self-assign a SIP number. A core developer reviews the draft for quality and ensure guidelines have been followed. 

**Proposed**
Prior to the start of mining on the Stacks blockchain, for a SIP to progress to the Proposed stage, acceptance from the core developer committee is required. Post-mining, the core developer team will review SIP’s for quality and adherence to guidelines only.

A core developer will move the SIP to the Proposed stage when the following has been satisfied:


1. Evidence of sufficient community support
2. All public criticism and comments have been adequately addressed

**Final/Active**
A SIP can be moved to the Final/Active status when a working reference implementation has been provided. Additionally, for a soft-fork SIP to progress to Final/Active status, a clear miner majority is required. Soft-fork BIPS themselves may set additional requirements. For a hard-fork SIP to progress to Final/Active status, adoption from the entire Stacks network economy is required. 

**Obsolete**
When a SIP is no longer relevant or is superseded by another SIP it’s status will change to Obsolete. 

**Deferred**
When no progress has been made on a SIP for a period of time, it can be marked as deferred.

**Rejected**
A SIP can be marked as rejected if the SIP is unable to gather enough community support.

**Withdrawn** 
The SIP author may choose to withdraw the SIP.

## SIP format and structure

The SIP should contain the following sections

**Preamble header**
A metadata header containing the following information:

- Title
- Author
- Status
- Type (Standard, Process or Informational)
- Created Date
- License
- Comments URL (Link to discussion for this SIP)
- Replaces/Superseded by (Optional)

**Abstract**
A short (~200 word) description of the issue being addressed.

**Specification**
The detailed description of the new feature or process.

**Rationale**
The rationale and motivation behind the new feature or process. It should describe any alternate designs and how the decision was made.

**Reference implementation**
Standards Track SIPs consist of two parts, a design document and a reference implementation. The SIP should be reviewed and accepted before a reference implementation is begun, unless a reference implementation will aid people in studying the SIP. Standards Track SIPs must include an implementation -- in the form of code, a patch, or a URL to same -- before it can be considered Final.

## SIP Types

**Standard**
A SIP of this type describes a new feature or improvement to the Stacks blockchain protocol that affects all Stacks blockchain implementations.

**Process**
A process SIP is a document describing a new process surrounding the Stacks blockchain.

**Informational**
An informational SIP describes a design issue or provides general guidelines. Users and implementors are free to ignore informational SIPs.

## SIP Comments

It is the responsibility of the author to circulate the SIP and gather input from the community. Comments on the SIP can be added directly to the GitHub pull request or on a SIP-specific discussion thread on the [Blockstack forums](https://forum.blockstack.org). In the latter case, the link to the forum thread should be indicated in the preamble header.

## Core Developer Committee

The core developer committee is a group of active contributors to the Stacks blockchain. They are tasked with reviewing SIPs and managing their progression. Initially the committee will consist of developers from Blockstack PBC. Membership will be opened to the community once mining begins. Nominations to join the committee may be submitted by an existing committee member and approval requires a majority of committee members.

## Copyright & Licensing

Each SIP must identify at least one acceptable license in its preamble. Source code in the SIP can be licensed differently than the text. Below is a list of recommended licenses.


- BSD-2-Clause: [OSI-approved BSD 2-clause license](https://opensource.org/licenses/BSD-2-Clause)
- BSD-3-Clause: [OSI-approved BSD 3-clause license](https://opensource.org/licenses/BSD-3-Clause)
- CC0-1.0: [Creative Commons CC0 1.0 Universal](https://creativecommons.org/publicdomain/zero/1.0/)
- GNU-All-Permissive: [GNU All-Permissive License](http://www.gnu.org/prep/maintain/html_node/License-Notices-for-Other-Files.html)
- GPL-2.0+: [GNU General Public License (GPL), version 2 or newer](http://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)
- LGPL-2.1+: [GNU Lesser General Public License (LGPL), version 2.1 or newer](http://www.gnu.org/licenses/old-licenses/lgpl-2.1.en.html)

