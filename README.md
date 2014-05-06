StrongBox
============
For execution help,
```bash
python StrongBox.py -h
```

## Demo Screencast
All in due time...

### What?

A working prototype of an encrypted, P2P file syncing system in the vein of OwnCloud (a self-hosted, client-server  system styled after the more famous DropBox). With StrongBox, users benefit from the accessibility and reliability of having redundant backups of their data without sacrificing privacy. Made as a final project submission for Professor Jim Waldo's Spring 2014 CS262 at Harvard (not bad for two weeks of coding!).

### Why?

With any "free" service, be it e-mail or file storage, there's always a hidden cost to make things worthwhile for the service provider. Generally, this payoff comes in the form of valuable information gleaned from analyzing users' data and potentially directed advertising based on that information. In other models, payed "premium" services are offered with paying users offsetting the cost of their own services and those of free-tier users.

StrongBox instead uses the peer-to-peer model so users can decide on their own terms for backing up one another's data. As originally conceived, this agreement would mean that each user offers the other some amount of storage space as well as the bandwidth required for synchronization and the electricity/maintenance costs associated with keeping their machine on.

Privacy is also of primary importance in StrongBox. In the wake of Edward Snowden's revelations about digital spying programs such as PRIZM, and tech companies' complicity therein, users' concerns about online privacy continue to increase as their confidence in businesses' handling of private data continues to decline [[1]](http://www.truste.com/about-TRUSTe/press-room/news_us_truste_reveals_consumers_more_concerned_about_data_collection) [[2]](http://www.pewinternet.org/2013/09/05/anonymity-privacy-and-security-online/). It has also been well established that the inability to store and communicate private data has a "chilling effect" on democracy and free speech [[3]](https://www.eff.org/press/releases/eff-files-22-firsthand-accounts-how-nsa-surveillance-chilled-right-association) [[4]](http://www.presstv.com/detail/2013/11/12/334416/us-writers-scared-silent-by-nsa-spying/).

StongBox makes abundant use of strong cryptography to ensure the privacy and integrity of a user's synced data. All communications between peers occur over encrypted SSL channels to prevent eavesdropping or the manipulation of communications. More importantly, StrongBox seamlessly AES-256 encrypts a user's synced data (including file and directory names) before it ever leaves their machine, so no one without the user's private encryption key can discover the original contents.

### What's missing?
* A chain of trust or certificate signing authority and cryptographically sound peer verification checks (currently a peer can be imitated, however all that would be gained by an imitator would be access to encrypted data).
* Automated backup association. As originally proposed, peers would bid storage space available to others and a central server would match peers with compatible bids and instruct the peers to act as backups for one-another. Currently, this is done on a uni-directional basis by moving a config file to the backing up peer via some side-band (e.g. copying via scp, sneakernet).