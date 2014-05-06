StrongBox
============
For execution help,
‘’‘bash
python StrongBox.py -h
‘’‘

### What?

A working prototype of an encrypted, P2P file syncing system in the vein of OwnCloud (a self-hosted, client-server  system styled after the more famous DropBox). With StrongBox, users benefit from the accessibility and reliability of having redundant backups of their data without sacrificing privacy and security. Made as a final project submission for Professor Jim Waldo's Spring 2014 CS262 at Harvard (not bad for two weeks of coding!).

### Why?

With any "free" service, be it e-mail or file storage, there's always a hidden cost to make things worthwhile for the service provider. Generally, this payoff comes in the form of valuable information gleaned from analyzing users' data and potentially directed advertising based on that information. In other models, payed "premium" services are offered with paying users offsetting the cost of their own services and those of free-tier users.

StrongBox instead uses the peer-to-peer model so users can decide on their own terms for backing up one another's data. As originally conceived, this agreement would mean that each user offers the other some amount of storage space as well as the bandwidth required for synchronization and the electricity/maintenance costs associated with keeping their machine on.

Privacy is also of primary importance in StrongBox. In the wake of Edward Snowden's revelations about digital spying programs such as PRIZM, and tech companies' complicity therein, users' concerns about online privacy continue to increase as their confidence in businesses' handling of private data continues to decline [[1]](http://www.truste.com/about-TRUSTe/press-room/news_us_truste_reveals_consumers_more_concerned_about_data_collection) [[2]](http://www.pewinternet.org/2013/09/05/anonymity-privacy-and-security-online/). It has also been well established that the inability to store and communicate private data has a "chilling effect" on democracy and free speech [[3]](https://www.eff.org/press/releases/eff-files-22-firsthand-accounts-how-nsa-surveillance-chilled-right-association) [[4]](http://www.presstv.com/detail/2013/11/12/334416/us-writers-scared-silent-by-nsa-spying/). In StrongBox, the privacy of a user's synced data is ensured by strong encryption because all private data (including file and directory names) is seamlessly AES-256 encrypted before ever being transmitted.