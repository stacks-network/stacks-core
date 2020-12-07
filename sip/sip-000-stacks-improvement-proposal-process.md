# SIP-000 Stacks Improvement Proposal Process

# Preamble

Title: Stacks Improvement Proposal Process

Author: Ken Liao <yukanliao@gmail.com>, Jude Nelson <jude@blockstack.com>

Status: Draft 

Consideration: Governance 

Type: Meta 

Created: 2020-06-23 

License: BSD-2-Clause 

Sign-off: 

# Abstract

A Stacks Improvement Proposal (SIP) is a design document that provides
information to the greater Stacks ecosystem's participants concerning the design
of the Stacks blockchain and its ongoing operation. Each SIP shall provide a
clear and concise description of features, processes, and/or standards for the
Stacks blockchain and its operators to adopt, with sufficient details provided
such that a reasonable practitioner may use the document to create an
independent but compatible implementation of the proposed improvement.

SIPs are the canonical medium by which new features are proposed and described,
and by which input from the Stacks ecosystem participants is collected. The SIP
Ratification Process is also described in this document, and provides the means
by which SIPs may be proposed, vetted, edited, accepted, rejected, implemented,
and finally incorporated into the Stacks blockchain's design, governance, and
operational procedures. The set of SIPs that have been ratified shall
sufficiently describe the design, governance, and operationalization of the
Stacks blockchain, as well as the means by which future changes to its official
design, implementation, operation, and governance may be incorporated.

# License and Copyright

This SIP is made available under the terms of the BSD-2-Clause license,
available at https://opensource.org/licenses/BSD-2-Clause.  This SIP’s copyright
is held by the Stacks Open Internet Foundation.

# Specification

Each SIP shall adhere to the same general formatting and shall be ratified
through the processes described by this document.

## Introduction

Blockchains are unique among distributed systems in that they also
happen to encode a social contract. By running a blockchain node, a user
implicitly agrees to be bound to the social contract's terms embedded within the
blockchain's software. These social contracts are elaborate constructions that
contain not only technical terms (e.g. "a block may be at most 1MB"), but also
economic terms (e.g. "only 21 million tokens may exist") and social terms (e.g.
"no money can leave this account" or "this transaction type was supported
before, but will now be ignored by the system") which the user agrees to uphold
by running a blockchain node.

It stands to reason that the Stacks blockchain is made of more than just
software; it is also made of the people who run it. As such, the act of
developing and managing the Stacks blockchain network includes the act of
helping its people coordinate and agree on what the blockchain is and what it
should do. To this end, this document proposes a process by which the Stacks
blockchain's users can conduct themselves to be the stewards of the blockchain
network in perpetuity.

The goals of this process are to ensure that anyone may submit a SIP in good
faith, that each SIP will receive fair and speedy good-faith consideration by
other people with the relevant expertise, and that any discussions and
decision-making on each SIP's ratification shall happen in public. To achieve
these ends, this document proposes a standard way of presenting a Stacks
Improvement Proposal (SIP), and a standard way of ratifying one.

Each SIP document contains all of the information needed to propose a
non-trivial change to the way in which the Stacks blockchain operates. This
includes both technical considerations, as well as operational and governance
considerations. This document proposes a formal document structure based on both
request-for-comments (RFC) practices in the Internet Engineering Task Force
(IETF), as well as existing blockchain networks.

SIPs must be ratified in order to be incorporated into the definition of what
the Stacks blockchain is, what it does, and how it operates. This document
proposes a ratification process based on existing governance processes from
existing open source projects (including Python, Bitcoin, Ethereum, and Zcash),
and makes provisions for creating and staffing various roles that people must
take on to carry out ratification (e.g. committees, editors, working groups and
so on).

This document uses the word “users” to refer specifically to people who
participate in the greater Stacks ecosystem.  This includes, but is not limited
to, people who mine blocks, people who contribute code, people who run nodes,
people who develop applications that rely on the Stacks blockchain, people who
use such applications, people involved in the project governance, and people
involved in operating software deployments.

## SIP Format

All SIPs shall be formatted as markdown files. Each section shall be
annotated as a 2nd-level header (e.g. `##`). Subsections may be added with
lower-level headers.

Each SIP shall contain the following sections, in the given order:

- _Preamble_. This section shall provide fields useful for categorizing the SIP.
  The required fields in all cases shall be:
    - _SIP Number_. Each SIP receives a unique number once it has been accepted
      for consideration for ratification (see below). This number is assigned to
      a SIP; its author does not provide it.
    - _Title_. A concise description of the SIP, no more than 20 words long.
    - _Author_. A list of names and email addresses of the SIP's author(s).
    - _Consideration_. What class of SIP this is (see below).
    - _Type_. The SIP track for consideration (see below).
    - _Status_. This SIP's point in the SIP workflow (see below).
    - _Created_. The ISO 8601 date when this SIP was created.
    - _License_. The content license for the SIP (see below for permitted
      licenses).
    - _Sign-off_. The list of relevant persons and their titles who have worked to
      ratify the SIP. This field is not filled in entirely until ratification,
      but is incrementally filled in as the SIP progresses through the ratification
      process.
- Additional SIP fields, which are sometimes required, include:
    - _Layer_. The logical layer of the Stacks blockchain affected. Must be one
    - of the following:
        - _Consensus (soft fork)_. For backwards-compatible proposals for
          transaction-processing.
        - _Consensus (hard fork)_. For backwards-incompatible proposals for
          transaction-processing.
        - _Peer Services_. For proposals to the peer-to-peer network protocol
          stack.
        - _API/RPC_. For proposals to the Stacks blockchain's official
          programmatic interfaces.
        - _Traits_. For proposals for new standardized Clarity trait definitions.
        - _Applications_. For proposals for standardized application protocols
          that interface with the Stacks blockchain.
    - _Discussions-To_. A mailing list where ongoing discussion of the SIP takes
      place.
    - _Comments-Summary_. The comments summary tone.
    - _Comments-URI_. A link to the Stacks blockchain wiki for comments.
    - _License-Code_. Abbreviation for code under a different license than the SIP
      proposal.
    - _Post-History_. Dates of posting the SIP to the Stacks mailing list, or a
      link to a thread with the mailing list.
    - _Requires_. A list of SIPs that must be implemented prior to this SIP.
    - _Replaces_. A list of SIPs that this SIP replaces.
    - _Superceded-By_. A list of SIPs that replace this SIP.

- _Abstract_. This section shall provide a high-level summary of the proposed
  improvement. It shall not exceed 5000 words.
- _Copyright_. This section shall provide the copyright license that governs the
  use of the SIP content. It must be one of the approved set of licenses (see
below).
- _Introduction_. This section shall provide a high-level summary of the
  problem(s) that this SIP proposes to solve, as well as a high-level
description of how the proposal solves them. This section shall emphasize its
novel contributions, and briefly describe how they address the problem(s). Any
motivational arguments and example problems and solutions belong in this
section.
- _Specification_. This section shall provide the detailed technical
  specification. It may include code snippits, diagrams, performance
evaluations, and other supplemental data to justify particular design decisions.
However, a copy of all external supplemental data (such as links to research
papers) must be included with the SIP, and must be made available under an
approved copyright license.
- _Related Work_. This section shall summarize alternative solutions that address
  the same or similar problems, and briefly describe why they are not adequate
solutions. This section may reference alternative solutions in other blockchain
projects, in research papers from academia and industry, other open-source
projects, and so on. This section must be accompanied by a bibliography of
sufficient detail such that someone reading the SIP can find and evaluate the
related works.
- _Backwards Compatibility_. This section shall address any
  backwards-incompatiblity concerns that may arise with the implementation of
this SIP, as well as describe (or reference) technical mitigations for breaking
changes. This section may be left blank for non-technical SIPs.
- _Activation_. This section shall describe the timeline, falsifiable criteria,
  and process for activating the SIP once it is ratified. This applies to both
technical and non-technical SIPs.  This section is used to unambiguously
determine whether or not the SIP has been accepted by the Stacks users once it
has been submitted for ratification (see below).
- _Reference Implementations_. This section shall include one or more references
  to one or more production-quality implementations of the SIP, if applicable.
This section is only informative — the SIP ratification process is independent
of any engineering processes (or other processes) that would be followed to
produce implementations.  If a particular implementation process is desired,
then a detailed description of the process must be included in the Activation
section.  This section may be updated after a SIP is ratified in order to
include an up-to-date listing of any implementations or embodiments of the SIP. 

Additional sections may be included as appropriate.

### Supplemental Materials

A SIP may include any supplemental materials as
appropriate (within reason), but all materials must have an open format
unencumbered by legal restrictions. For example, an LibreOffice `.odp`
slide-deck file may be submitted as supplementary material, but not a Keynote
`.key` file.

When submitting the SIP, supplementary materials must be present within the same
directory, and must be named as `SIP-XXXX-YYY.ext`, where:

- `XXXX` is the SIP number,
- `YYY` is the serial number of the file, starting with 1,
- `.ext` is the file extension.

## SIP Types

The types of SIPs are as follows:

- _Consensus_. This SIP type means that all Stacks blockchain implementations
  would need to adopt this SIP to remain compatible with one another. If this is
the SIP type, then the SIP preamble must have the Layer field set to either
_Consensus (soft fork)_ or _Consensus (hard fork)_.
- _Standard_. This SIP type means that the proposed change affects one or more
  implementations, but does not affect network consensus. If this is the SIP
type, then the SIP preamble must have the Layer field set to indicate which
aspect(s) of the Stacks blockchain are affected by the proposal.
- _Operation_. This SIP type means that the proposal concerns the operation of the
  Stacks blockchain -- in particular, it concerns node operators and miners.
The difference between this SIP type and the Standard type is that this type
does not change any existing protocols.
- _Meta_. This SIP type means that the proposal concerns the SIP ratification
  process. Such a SIP is a proposal to change the way SIPs are handled.
- _Informational_. This is a SIP type that provides useful information, but does
  not require any action to be taken on the part of any user.

New types of SIPs may be created with the ratification of a Meta-type SIP under
the governance consideration (see below). SIP types may not be removed.

## SIP Considerations

A SIP's consideration determines the particular steps needed to ratify the SIP
and incorporate it into the Stacks blockchain. Different SIP considerations have
different criteria for ratification. A SIP can have more than one consideration,
since a SIP may need to be vetted by different users with different domains of
expertise.


- _Technical_. The SIP is technical in nature, and must be vetted by users with
  the relevant technical expertise.
- _Economic_. The SIP concerns the blockchain's token economics. This not only
  includes the STX token, but also any on-chain tokens created within smart
contracts. SIPs that are concerned with fundraising methods, grants, bounties,
and so on also belong in this SIP track.
- _Governance_. The SIP concerns the governance of the Stacks blockchain,
  including the SIP process. This includes amendments to the SIP Ratification
Process, as well as structural considerations such as the creation (or removal)
of various committees, editorial bodies, and formally recognized special
interest groups. In addition, governance SIPs may propose changes to the way by
which committee members are selected.
- _Ethics_. This SIP concerns the behaviors of office-holders in the SIP
  Ratification Process that can affect its widespread adoption.  Such SIPs
describe what behaviors shall be deemed acceptable, and which behaviors shall be
considered harmful to this end (including any remediation or loss of privileges
that misbehavior may entail).  SIPs that propose formalizations of ethics like
codes of conduct, procedures for conflict resolution, criteria for involvement
in governance, and so on would belong in this SIP consideration.
- _Diversity_. This SIP concerns proposals to grow the set of users, with an
  emphasis on including users who are traditionally not involved with
open-source software projects. SIPs that are concerned with evangelism,
advertising, outreach, and so on must have this consideration.

Each SIP consideration shall have a dedicated Advisory Board that ultimately
vets SIPs under their consideration for possible ratification in a timely
fashion (see below).  New considerations may be created via the ratification of
a Meta-type SIP under the governance consideration.

## SIP Workflow

As a SIP is considered for ratification, it passes through multiple statuses as
determined by one or more committees (see next section). A SIP may have exactly
one of the following statuses at any given time:

- _Draft_. The SIP is still being prepared for formal submission. It does not yet
  have a SIP number.
- _Accepted_. The SIP text is sufficiently complete that it constitutes a
  well-formed SIP, and is of sufficient quality that it may be considered for
ratification. A SIP receives a SIP number when it is moved into the Accepted
state by SIP Editors.
- _Recommended_. The people responsible for vetting the SIPs under the
  consideration(s) in which they have expertise have agreed that this SIP should
be implemented. A SIP must be Accepted before it can be Recommended.
- _Activation-In-Progress_.  The SIP has been tentatively approved by the Steering
  Committee for ratification.  However, not all of the criteria for ratification
have been met according to the SIP’s Activation section.  For example, the
Activation section might require miners to vote on activating the SIPs’
implementations, which would occur after the SIP has been transferred into
Activation-In-Progress status but before it is transferred to Ratified status.
- _Ratified._ The SIP has been activated according to the procedures described in
  its Activation section.  Once ratified, a SIP remains ratified in perpetuity,
but a subsequent SIP may supersede it. If the SIP is a Consensus-type SIP, and
then all Stacks blockchain implementations must implement it. A SIP must be
Recommended before it can be Ratified. Moving a SIP into this state may be done
retroactively, once the SIP has been activated according to the terms in its
Activation section.
- _Rejected_. The SIP does not meet at least one of the criteria for ratification
  in its current form. A SIP can become Rejected from any state, except
Ratified.  If a SIP is moved to the Rejected state, then it may be re-submitted
as a Draft.
- _Obsolete_. The SIP is deprecated, but its candidacy for ratification has not
  been officially withdrawn (e.g. it may warrant further discussion).  An
Obsolete SIP may not be ratified, and will ultimately be Withdrawn.
- _Replaced_. The SIP has been superseded by a different SIP.  Its preamble must
  have a Superseded-By field. A Replaced SIP may not be ratified, nor may it be
re-submitted as a Draft-status SIP.  It must be transitioned to a Withdrawn
state once the SIP(s) that replace it have been processed.
- _Withdrawn_. The SIP's authors have ceased working on the SIP. A Withdrawn SIP
  may not be ratified, and may not be re-submitted as a Draft.  It must be
re-assigned a SIP number if taken up again.
    

The act of ratifying a SIP is the act of transitioning it to the Ratified status
-- that is, moving it from Draft to Accepted, from Accepted to Recommended, and
Recommended to Activation-In-Progress, and from Activation-In-Progress to
Ratified, all without the SIP being transitioned to Rejected, Obsolete,
Replaced, or Withdrawn status.  A SIP's current status is recorded in its Status
field in its preamble.

## SIP Committees

The act of deciding the status of a SIP is handled by a set of designated
committees. These committees are composed of users who dedicate their time and
expertise to curate the blockchain, ratifying SIPs on behalf of the rest of the
ecosystem’s users.

There are three types of committee:

- _Steering Committee (SC)_. The roles of the SC are to select Recommended-status
  SIPs to be activated, to determine whether or not a SIP has been activated and
thus ratified, and to formally recognize Consideration Advisory Boards (see
below).
- _Consideration Advisory Boards_. The roles of the Consideration Advisory Boards
  are to provide expert feedback on SIPs that have been moved to Accepted status
in a timely manner, and to transition SIPs to Recommended status if they meet
the Board's consideration criteria, and Rejected status otherwise. 
- _SIP Editors_. The role of the SIP Editors is to identify SIPs in the Draft
  status that can be transitioned to Accepted status. A SIP editor must be able
to vet a SIP to ensure that it is well-formed, that it follows the ratification
workflow faithfully, and that it does not overlap with any already-Accepted SIPs
or SIPs that have since become Recommended or Ratified.
    
Any user may serve on a committee. However, all Stacks committee members must
abide by the SIP Code of Conduct and must have a history of adhering to it.
Failure to adhere to the Code of Conduct shall be grounds for immediate removal
from a committee, and a prohibition against serving on any future committees.

### Compensation

Compensation for carrying out committee duties is outside of the scope of this
document.  This document does not create a provision for compensation for
committee participation, but it does not forbid it either.

### Steering Committee Duties

The Steering Committee's overarching duty is to oversee the evolution of the
Stacks blockchain’s design, operation, and governance, in a way that is
technically sound and feasible, according to the rules and procedures described
in this document. The SC shall be guided by and held accountable by the greater
community of users, and shall make all decisions with the advice of the relevant
Consideration Advisory Boards. 

The SC’s role is that of a steward.  The SC shall select SIPs for ratification
based on how well they serve the greater good of the Stacks users.  Given the
nature of blockchains, the SC's particular responsibilities pertaining to
upgrading the blockchain network are meant to ensure that upgrades happen in a
backwards-compatible fashion if at all possible. While this means that more
radical SIPs may be rejected or may spend a long amount of time in Recommended
status, it also minimizes the chances of an upgrade leading to widespread
disruption (the minimization of which itself serves the greater good).

#### Membership

The initial Steering Committee shall be comprised of at least three members:
two from the Stacks Open Internet Foundation, and one
from the greater Stacks blockchain community (independent of the Stacks
Foundation).

A provisional Steering Committee will be appointed by the Stacks Open Internet Foundation Board
before the launch of the Stacks blockchain’s mainnet (see the "Activation" section).
Once this SIP activates, the Stacks Open Internet Foundation shall select its
representatives in a manner of their choosing within 90 days after activation.
The committee may be expanded later to include more seats.  Once this SIP
activates, the provisional SC will consult with the community to
ratify a SIP that implements a voting procedure whereby
Stacks community members can select the individual who will serve on the
community SC seat.

#### Qualifications

Members of this committee must have deep domain expertise
pertinent to blockchain development, and must have excellent written
communication skills. It is highly recommended that members should have authored
at least one ratified technical-consideration SIP before joining this committee.

#### Responsibilities

The Steering Committee shall be responsible for the following
tasks.

##### Recognizing Consideration Advisory Boards.

The members of the Steering Committee
must bear in mind that they are not infallible, and that they do not know everything
there is to know about what is best for the broader user community. To the
greatest extent practical, the SC shall create and foster the development of
Consideration Advisory Boards in order make informed decisions on subjects that
in which they may not be experts.

Any group of users can form an unofficial working group to help provide feedback
to SIPs, but the SC shall have the power to recognize such groups formally as a
Consideration Advisory Board via at least a two-thirds majority vote. The SC
shall simultaneously recognize one of it’s member to serve as the interim
chairperson while the Advisory Board forms. A SC member cannot normally serve on
a Consideration Advisory Board concurrently with serving on the SC, unless
granted a limited exception by a unanimous vote by the SC (e.g. in order to
address the Board’s business while a suitable chairperson is found).  Formally
recognizing Consideration Advisory Boards shall occur in Public Meetings (see
below) no more than once per quarter.

Once recognized, Consideration Advisory Boards may not be dissolved or
dismissed, unless there are no Accepted or Recommended SIPs that request their
consideration. If this is the case, then the SC may vote to rescind recognition
of a Consideration Advisory Board with a two-thirds majority at one of its
Public Meetings.

In order to identify users who would form a Consideration Advisory Board, users
should organize into an unofficial working group and submit a SIP to petition
that SC recognize the working group as a Consideration Advisory Board.  This
petition must take the form of a Meta-type SIP, and may be used to select the
initial chairperson and define the Board's domain(s) of expertise, bylaws,
membership, meeting procedures, communication channels, and so on, independent
of the SC. The SC would only be able to ratify or reject the SIP.

The SC shall maintain a public index of all Consideration Advisory Boards that
are active, including contact information for the Board and a summary of what
kinds of expertise the Board can offer. This index is meant to be used by SIP
authors to help route their SIPs towards the appropriate reviewers before being
taken up by the SC.

##### Voting on Technical SIPs

The Steering Committee shall select Recommended SIPs
for ratification by moving them to Activation-In-Progress status.  All
technical-consideration SIPs shall require an 80% vote. If it is a
Consensus-type SIP for a hard fork, then a unanimous vote shall be required. If
a SIP is voted on and is not moved to Activation-in-Progress, then it shall be
moved to Rejected status, and the SC shall provide a detailed explanation as to
why they made their decision (see below).

##### Voting on Non-technical SIPs

Not all SIPs are technical in nature. All
non-technical SIPs shall require only a two-thirds majority vote to transition
it to Activation-In-Progress status. The SC members must provide a public
explanation for the way it voted as supplementary materials with the ratified
non-technical SIP (see below).  If the SC votes to move a non-technical SIP to
Activation-In-Progress status, but does not receive the requisite number of
votes, then the SIP shall be transferred to Rejected status, and the SC shall
provide a detailed explanation as to why they made their decision (see below).

##### Overseeing SIP Activation and Ratification

Once a SIP is in Activation-In-Progress status,
the SC shall be responsible for overseeing the procedures and criteria in the
SIP’s Activation section.  The Activation section of a SIP can be thought of as
an “instruction manual” and/or “checklist” for the SC to follow to determine if
the SIP has been accepted by the Stacks users.  The SC shall strictly adhere to
the process set forth in the Activation section.  If the procedure and/or
criteria of the Activation section cannot be met, then the SC may transfer the
SIP to Rejected status and ask the authors to re-submit the SIP with an updated
Activation section.

Once all criteria have been unambiguously meet and all activation procedures
have been followed, the SC shall transition the SIP to Ratified status.  The SC
shall keep a log and provide a record of the steps they took in following a
SIP’s Activation section once the SIP is in Activation-In-Progress status, and
publish them alongside the Ratified SIP as supplemental material.

Due to the hands-on nature of the Activation section, the SC may deem it
appropriate to reject a SIP solely on the quality of its Activation section.
Reasonable grounds for rejection include, but are not limited to, ambiguous
instructions, insufficiently-informative activation criteria, too much work on
the SC members’ parts, the lack of a prescribed activation timeout, and so on.

Before the Stacks mainnet launches, the SC shall ratify a SIP that, when
activated according to the procedures outlined in its Activation section, will
allow Stacks blockchain miners to signal their preferences for the activation of
particular SIPs within the blocks that they mine. This will enable the greater
Stacks community of users to have the final say as to which SIPs activate and
become ratified.

##### Feedback on Recommended SIPs

The Steering Committee shall give a full, fair,
public, and timely evaluation to each SIP transitioned to Recommended status by
Consideration Advisory Boards. A SIP shall only be considered by the SC if the
Consideration Advisory Board chairpeople for each of the SIP's considerations
have signed-off on the SIP (by indicating as such on the SIP's preamble). 

The SC may transition a SIP to Rejected status if it disagrees with the
Consideration Advisory Boards' recommendation. The SC may transition a SIP to
Obsolete status if it finds that the SIP no longer addresses a relevant concern.
It may transition the SIP to a Replaced status if it considers a similar,
alternative SIP that is more likely to succeed. In all cases, the SC shall
ensure that a SIP does not remain in Recommended status for an unreasonable
amount of time.

The SC shall maintain a public record of all feedbacks provided for each SIP it
reviews.

If a SIP is moved to Rejected, Obsolete, or Replaced status, the SIP authors may
appeal the process by re-submitting it in Draft status once the feedback has
been addressed.  The appealed SIP must cite the SC’s feedback as supplemental
material, so that SIP Editors and Consideration Advisory Boards are able to
verify that the feedback has, in fact, been addressed.

##### Public Meetings

The Steering Committee shall hold and record regular public
meetings at least once per month. The SC may decide the items of business for
these meetings at its sole discretion, but it shall prioritize business
pertaining to the ratification of SIPs, the recognition of Consideration
Advisory Boards, and the needs of all outstanding committees. That said, any
user may join these meetings as an observer, and the SC shall make a good-faith
effort to address public comments from observers as time permits.

The SC shall appoint up to two dedicated moderators from the user community for
its engineering meetings, who shall vet questions and commentary from observers
in advance (possibly well before the meeting begins). If there is more than one
moderator, then the moderators may take turns. In addition, the SC shall appoint
a dedicated note-taker to record the minutes of the meetings. All of these
appointees shall be eligible to receive a fixed, regular bounty for their work.

### Consideration Advisory Board Duties

There is an Advisory Board for each SIP consideration, with a designated
chairperson responsible for maintaining copies of all discussion and feedback on
the SIPs under consideration.

#### Membership

All Consideration Advisory Boards begin their life as unofficial
working groups of users who wish to review inbound SIPs according to their
collective expertise.  If they wish to be recognized as an official
Consideration Advisory Board, they shall submit a SIP to the Steering Committee
per the procedure described in the Steering Committee’s duties.  Each
Consideration Advisory Board shall be formally created by the SC with a
designated member serving as its first interim chairperson. After this, the
Consideration Advisory Board may adopt its own bylaws for selecting members and
chairpeople. However, members should have domain expertise relevant to the
consideration.

#### Members

shall serve on their respective Consideration Advisory Boards so long as
they are in good standing with the SIP Code of Conduct and in accordance to the
individual Board’s bylaws.  A user may serve on at most three Consideration
Advisory Boards concurrently.

#### Qualifications

Each Consideration Advisory Board member shall have sufficient
domain expertise to provide the Steering Committee with feedback pertaining to a
SIP's consideration. Members shall possess excellent written communication
skills.

#### Responsibilities

Each Consideration Advisory Board shall be responsible for the
following.

##### Chairperson

Each Consideration Advisory Board shall appoint a chairperson, who
shall serve as the point of contact between the rest of the Board and the
Steering Committee. If the chairperson becomes unresponsive, the SC may ask the
Board to appoint a new chairperson (alternatively, the Board may appoint a new
chairperson on its own and inform the SC).  The chairperson shall be responsible
for maintaining the Board’s public list of members’ names and contact
information as a supplementary document to the SIP that the SC ratified to
recognize the Board.

##### Consideration Track

Each Consideration Advisory Board shall provide a clear and
concise description of what expertise it can offer, so that SIP authors may
solicit it with confidence that it will be helpful. The chairperson shall make
this description available to the Steering Committee and to the SIP Editors, so
that both committees can help SIP authors ensure that they receive the most
appropriate feedback.

The description shall be provided and updated by the chairperson to the SC so
that the SC can provide a public index of all considerations a SIP may possess.

##### Feedback

to SIP Authors Each Consideration Advisory Board shall provide a full,
fair, public, and timely evaluation of any Accepted-status SIP that lists the
Board's consideration in its preamble. The Board may decide to move each SIP to
a Recommended status or a Rejected status based on whether or not the Board
believes that the SIP is feasible, practical, and beneficial to the greater
Stacks ecosystem.

Any feedback created shall be made public. It is the responsibility of the Board
to store and publish all feedbacks for the SIPs it reviews. It shall forward
copies of this feedback to both the SIP authors.

##### Consultation with the Steering Committee

The Steering Committee may need to
follow up with the Consideration Advisory Board in order to clarify its position
or solicit its advice on a particular SIP. For example, the SC may determine
that a Recommended SIP needs to be considered by one or more additional Boards
that have not yet been consulted by the SIP authors.

The Board shall respond to the SC's request for advice in a timely manner, and
shall prioritize feedback on SIPs that are under consideration for ratification.

### SIP Editor Duties

By far the largest committee in the SIP process is the SIP Editor Committee.
The SIP Editors are responsible for maintaining the "inbound funnel" for SIPs
from the greater Stacks community. SIP Editors ensure that all inbound SIPs are
well-formed, relevant, and do not duplicate prior work (including rejected
SIPs).

#### Membership

Anyone may become a SIP Editor by recommendation from an existing SIP
Editor, subject to the “Recruitment” section below.

#### Qualifications

A SIP Editor must demonstrate proficiency in the SIP process and
formatting requirements. A candidate SIP Editor must demonstrate to an existing
SIP Editor that they can independently vet SIPs.

#### Responsibilities

SIP Editors are concerned with shepherding SIPs from Draft
status to Accepted status, and for mentoring community members who want to get
involved with the SIP processes (as applicable).

##### Getting Users Started

SIP Editors should be open and welcoming towards
enthusiastic users who want to help improve the greater Stacks ecosystem. As
such, SIP Editors should encourage users to submit SIPs if they have good ideas
that may be worth implementing.

In addition, SIP Editors should respond to public requests for help from
community members who want to submit a SIP. They may point them towards this
document, or towards other supplemental documents and tools to help them get
started.

##### Feedback

When a SIP is submitted in Draft status, a SIP Editor that takes the
SIP into consideration should provide fair and full feedback on how to make the
SIP ready for its transition to Accepted status. 

To do this, the SIP Editor should:

- Verify that the SIP is well-formed according to the criteria in this document
- Verify that the SIP has not been proposed before
- Verify as best that they can that the SIP is original work
- Verify that the SIP is appropriate for its type and consideration
- Recommend additional Considerations if appropriate
- Ensure that the text is clear, concise, and grammatically-correct English
- Ensure that there are appropriate avenues for discussion of the SIP listed in
  the preamble.

The SIP Editor does not need to provide public feedback to the SIP authors, but
should add their name(s) to the Signed-off field in the SIP preamble once the
SIP is ready to be Accepted.

##### Acceptance

Once a SIP is moved to Accepted, the SIP Editor shall assign it the
smallest positive number not currently used to identify any other SIP. Once that
number is known, the SIP Editor shall set the SIP's status to Accepted, set the
number, and commit the SIP to the SIP repository in order to make it visible to
other SIP Editors and to the Consideration Advisory Boards.

##### Recruitment

Each SIP Editor must list their name and contact information in an
easy-to-find location in the SIP repository, as well list of each SIP Editor
they recommended.  In so doing, the SIP Editors shall curate an “invite tree”
that shows which Editors recommended which other Editors.

A SIP Editor may recommend another user to be a SIP Editor no more than once per
month, and only if they have faithfully moved at least one SIP to Accepted
status in the last quarter.  If a SIP Editor does not participate in editing a
SIP for a full year and a day, then they may be removed from the SIP Editor
list.  The SC may remove a SIP Editor (and some or all of the users he or she
recommended) if they find that the SIP Editor has violated the SIP Code of
Conduct.

Newly-Accepted SIPs, new SIP Editor recruitment, and SIP Editor retirement shall
be submitted as pull requests by SIP Editors to the SIP repository.

## SIP Workflow

The lifecycle of a SIP is summarized in the flow-chart below:

```
    ------------------
    |     Draft      |  <-------------------------. Revise and resubmit
    ------------------                            |
           |                             --------------------
    Submit to SIP Editor ------------->  |     Rejected     |
           |                             --------------------
           |                                      ^
           V                                      |
    ------------------                            |
    |   Accepted     | -------------------------/ | /--------------------------------.
    ------------------                            |                                  |
           |                             --------------------                        |
    Review by Consideration ---------->  |     Rejected     |                        | 
    Advisory Board(s)                    --------------------                        |
           |                                      ^                                  |
           V                                      |                                  |
    -------------------------                     |                                  |
    |      Recommended       | -----------------/ | /------------------------------->|
    -------------------------                     |                                  |
           |                              --------------------                       |
    Vote by the Steering    ----------->  |    Rejected      |                       |
    Committee for activation              --------------------                       |
           |                                      ^                                  |
           V                                      |                                  |
    --------------------------                    |                                  |
    | Activation-in-Progress | -----------------/ | /------------------------------->|
    --------------------------                    |                                  |
           |                             ---------------------                       |
    All activation  ------------------>  |     Rejected      |                       |
    criteria are met       |             ---------------------  ------------------   |
           |               |----------------------------------> |    Obsolete    |   |
           V               |      ---------------------         ------------------   |
    ------------------     *--->  |     Replaced      | --------------->|<-----------*
    |   Ratified     |            ---------------------                 | 
    ------------------                                                  V
                                                                -------------------
                                                                |    Withdrawn    |
                                                                ------------------- 
```

When a SIP is transitioned to Rejected, it is not deleted, but is preserved in
the SIP repository so that it can be referenced as related or prior work by
other SIPs. Once a SIP is Rejected, it may be re-submitted as a Draft at a later
date. SIP Editors may decide how often to re-consider rejected SIPs as an
anti-spam measure, but the Steering Committee and Consideration Advisory Boards
may opt to independently re-consider rejected SIPs at their own discretion.

## Public Venues for Conducting Business

The canonical set of SIPs in all state shall be recorded in the same medium that
the canonical copy of this SIP is.  Right now, this is in the Github repository
https://github.com/stacksorg/sips, but may be changed before this SIP is
ratified.  New SIPs, edits to SIPs, comments on SIPs, and so on shall be
conducted through Github's facilities for the time being.

In addition, individual committees may set up and use public mailing lists for
conducting business.  The Stacks Open Internet Foundation shall provide a means
for doing so.  Any discussions on the mailing lists that lead to non-trivial
contributions to SIPs should be referenced by these SIPs as supplemental
material.

### Github-specific Considerations

All SIPs shall be submitted as pull requests, and all SIP edits (including status
updates) shall be submitted as pull requests.  The SC, or one or more
individuals or entities appointed by the SC, shall be responsible for merging
pull requests to the main branch.

## SIP Copyright & Licensing

Each SIP must identify at least one acceptable license in its preamble. Source
code in the SIP can be licensed differently than the text. SIPs whose reference
implementation(s) touch existing reference implementation(s) must use the same
license as the existing implementation(s) in order to be considered. Below is a
list of recommended licenses.

- BSD-2-Clause: OSI-approved BSD 2-clause license
- BSD-3-Clause: OSI-approved BSD 3-clause license
- CC0-1.0: Creative Commons CC0 1.0 Universal
- GNU-All-Permissive: GNU All-Permissive License
- GPL-2.0+: GNU General Public License (GPL), version 2 or newer
- LGPL-2.1+: GNU Lesser General Public License (LGPL), version 2.1 or newer

# Related Work

The governance process proposed in this SIP is inspired by the Python PEP
process [1], the Bitcoin BIP2 process [2], the Ethereum Improvement Proposal [3]
processes, the Zcash governance process [4], and the Debian GNU/Linux
distribution governance process [5].  This SIP describes a governance process
where top-level decision-making power is vested in a committee of elected
representatives, which distinguishes it from Debian (which has a single elected
project leader), Python (which has a benevolent dicator for life), and Bitcoin
and ZCash (which vest all decision ratification power solely in the blockchain
miners).  The reason for a top-level steering committee is to ensure that
decision-making power is not vested in a single individual, but also to ensure
that the individuals responsible for decisions are accountable to the community
that elects them (as opposed to only those who have the means to participate
in mining).  This SIP differs from Ethereum's governance
process in that the top-level decision-making body (the "Core Devs" in Ethereum,
and the Steering Committee in Stacks) is not only technically proficient to evaluate
SIPs, but also held accountable through an official governance
process.

[1] https://www.python.org/dev/peps/pep-0001/

[2] https://github.com/bitcoin/bips/blob/master/bip-0002.mediawiki

[3] https://eips.ethereum.org/

[4] https://www.zfnd.org/governance/

[5] https://debian-handbook.info/browse/stable/sect.debian-internals.html

# Activation

This SIP activates once following tasks have been carried out:

- The provisional Steering Committee must be appointed by the Stacks Open Internet
  Foundation Board.
- Mailing lists for the initial committees must be created.
- The initial Consideration Advisory Boards must be formed, if there is interest
  in doing so before this SIP activates.
- A public, online SIP repository must be created to hold all non-Draft SIPs, their edit
  histories, and their feedbacks.
- A directory of Consideration Advisory Boards must be established (e.g. within
  the SIP repository).
- A SIP Code of Conduct should be added as a supplemental document
- The Stacks blockchain mainnet must launch.

# Reference Implementation

Not applicable.

# Frequently Asked Questions

NOTE: this section will be expanded as necessary before ratification
