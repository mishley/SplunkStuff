# SplunkStuff
Random useful Splunk stuff I've written.
## splunk_unity.pm
* splunk OutputPlugin for Sourcefire eStreamer
* drop-in replacement for the app hosted on Splunk apps (the one that sucked)
* Intended for version < 5.x
* No lookups because that's stupid
* No PDML because that's stupid
* Packet data inline in alert since it's small
* I think SF fixed a lot of this pre-Cisco acquisition with an app they hosted, and of course 5.x changed a lot

## scrabble.py
* Implemented a custom Splunk SPL command to do calculations on string scrabble scores or entropy.
* Verified to work in Splunk 6.3. Distributed search command to calculate scrabble scores of strings (@mgeide idea I borrowed) and Shannon entropy. NOT inspired by @rkovar splunk entropy blog post at http://blogs.splunk.com/author/rkovar/ but you should read it anyways, it's a great post. :)
