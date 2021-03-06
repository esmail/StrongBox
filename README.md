StrongBox [![Build Status](https://travis-ci.org/esmail/StrongBox.svg?branch=master)](https://travis-ci.org/esmail/StrongBox) [![Coverage Status](https://coveralls.io/repos/esmail/StrongBox/badge.png?branch=master)](https://coveralls.io/r/esmail/StrongBox?branch=master)
============
For execution help, run the command:
```bash
StrongBox.py -h
```

## Demo Screencast
All in due time...

### What?

A working prototype of an encrypted, P2P file syncing system in the vein of OwnCloud (self-hosted) or DropBox (third-party) written in Python. With StrongBox, users benefit from the accessibility and reliability of having redundant backups of their data without sacrificing privacy. Made as a final project submission for Professor Jim Waldo's Spring 2014 CS-262 at Harvard with the initial working implementation coded in two weeks.

### Why?

With any "free" service--be it e-mail, file storage, or free checking accounts--there's always a hidden cost to make things worthwhile for the service provider. On the internet, this payoff generally comes in the form of marketable information gleaned from analyzing users' data and habits as well as directed advertising based on that information. In other models, payed "premium" services are offered and paying users additionally offset the cost of their own services and those of free-tier users.

StrongBox instead uses the peer-to-peer model so users can customize the terms for backing up one another's data. As originally conceived, this agreement would mean that each user offers the other some amount of storage space as well as the bandwidth required for synchronization and the electricity/maintenance costs associated with keeping their machine on (an always-on program should be up front about the potential for such costs and [environmental impacts](http://www.bitcarbon.org/bitcarbon/)). By syncing their data to other StrongBox peers, a user benefits from the increased accessibility and failure independence of redundant, geographically distributed backups.

Privacy is also of primary importance in StrongBox. In the wake of Edward Snowden's revelations about digital spying programs such as PRISM and tech companies' complicity therein, users' concerns about online privacy continue to increase as their confidence in businesses' handling of private data continues to decline [[1]](http://www.truste.com/about-TRUSTe/press-room/news_us_truste_reveals_consumers_more_concerned_about_data_collection) [[2]](http://www.pewinternet.org/2013/09/05/anonymity-privacy-and-security-online/). It has also been well established that such invasions of privacy have a "chilling effect" on democracy and free speech [[3]](https://www.eff.org/press/releases/eff-files-22-firsthand-accounts-how-nsa-surveillance-chilled-right-association) [[4]](http://www.presstv.com/detail/2013/11/12/334416/us-writers-scared-silent-by-nsa-spying/).

This is why StongBox makes abundant use of strong cryptography to ensure the privacy and integrity of a user's synced data. All communications between peers occur over encrypted SSL channels to prevent eavesdropping or the manipulation of communications. More importantly, StrongBox seamlessly AES-256 encrypts a user's synced data (including file and directory names) before it ever leaves their machine, so synced data is cryptographically guaranteed to be unintelligible to any party that is not holding the user's private encryption key. Furthermore, these guarantees don't come at the cost of convenience as is frequently the case when securing one's data. A user is free to modify their files as usual while StrongBox takes care of the encryption and synchronization in the background.


### How?

There are three primary concepts at work in the exectution of StrongBox: **stores**, **revisions**, and **peers**.

##### Stores

A store is the directory of files and subdirectories a user wants to have synced and will be backed up in its entirety to associated backup peers and the user's other machines. On the store owner's machine(s), the store directory is just like any other and can have its contents read or modified at will. However, a peer backing up a store will receive its contents in encrypted form as all store data (including file names and directory names) are AES-256 encrypted before ever leaving the owner's machine(s). 

To verify that an encrypted backup hasn't been partially deleted or otherwise tampered with, backup integrity is checked using a SHA-256 Merkle tree (or hash tree) implementation for use with filesytem directories. When requesting verification from a backup peer, the store owner (alternatively another backup peer) will generate a random nonce (or "salt") with which the backup peer is to compute the overall hash value of the Merkle tree. If the backup peer's resulting hash matches the nonced hash computed by the requester, the integrity of the backup is cryptographically ensured. Merkle trees are also used to identify when two copies of a store are out of sync and the specific (encrypted) files and directories that differ between the two.


##### Revisions

A revision of a store can be thought of as a cohesive state of the store at some point in time. A store owner's StrongBox instance will monitor their store directory and upon detecting a change will signal for new revision data to be generated. Revisions are given numbers in the spirit of Lamport's logical clocks to give sequentiality to the changes a store undergoes. To these revision numbers are attached the overall Merkle tree hash for the store and an RSA-4096 digital signature covering both revision number and hash. The revision hash allows backup peers and the owner's other StrongBox instances to independently verify the integrity of their copy of the store. The digital signature prevents network errors or malicious peers from manipulating revision data. A malicious peer could still retransmit old signed data (a replay attack), but the presence of the revision number allows up to date peers to detect the stale data.

##### Peers

A peer is a running instance of StrongBox, syncing its owner's store. StrongBox peers interact directly with one another. During communication, peers "gossip" to one another about the state of other peers to quickly disseminate information across the system. For example, peer A might gossip to peer B, "peer C doesn't have a valid revision of store X and needs an update," or "peer D just entered the system at network address Z and might be of interest to you." Through the course of communications, two peers will come to an agreement on which mutually held store they will sync on and what type of sync each will be undertaking (send, receive, or verify).


#### Do You Want More?!!!??!
Check out the Sphinx-generated API documentation [here](https://esmail.github.io/StrongBox/sphinx/html/index.html).

### What's missing?
* A GUI!
* A chain of trust or certificate signing authority and cryptographically sound peer verification checks. Currently a peer can be imitated, however the imitator would only gain access to encrypted data and would be unable to convince other peers to modify the state of any previously known store.
* Automated backup association. As originally proposed, peers would bid storage space available to others and a central server would match peers with compatible bids and instruct the peers to act as backups for one-another. Currently, this is done on a uni-directional basis by moving a config file to the backing up peer via some side-band (e.g. copying via scp, sneakernet).
* Paxos. Currently, if a user updates their store on one of their machines and then makes subsequent changes on another of their machines that did not retrieve the original update (a "split brain" scenario), StrongBox will not be able to choose between the two and only the changes on the machine that makes the next (third) update will be kept. This could be remedied by requiring each revision to enact a Paxos-style two-phase commit e.g. using Doozer as a Paxos implementation.
* Staging sync changes before committing. This would allow a peer to verify the changes they received before moving them into place.
* Support for the user updating their private encryption key.
