 
# Web of Trust Concept in IoT

This is a refined transcript of our meeting from 03 Feb 2022. Please feel free to comment and challenge! It might not be accurate enough yet. - Frank

The core problem is the establishment of mutual trust between a big set of IoT devices, e.g., by providing encryption keys for DTLS communication, for each individual pair of devices.
For example in the RIOT DTLS example, pre shared keys (psk) or public keys have to be stored for each connected device, which is not a feasible solution for the productive environment.

When we use symmetric key encryption (public/private keys), a means to retrieve a public key of a desired communication partner is required.
When Alice wants to communicate with Bob, Alice needs to retrieve the public key of Bob first.
But this process can always be compromised.

The proposed solution we address is a scalable WoT infrastructure, where we introduce resource directories (RDs) to store public keys of devices.
Each RD stores the public keys of their associated IoT devices, and can issue these public keys, in form of certificates, to any potential communication partner.

Therefore, when an IoT device enters the network, it goes through the following steps:

1. It registers with the next RD. 
The RD can be found through CoAP service discovery, but for simplicity, it can be just hard coded for the implementation part of the thesis.
2. It establishes trust to the RD.
This is similar to the key signing process in WoT.
It can either be done with a hard-coded psk, or with a hard coded "root certificate" that solely serves this single purpose.
3. After the trust establishment, both the device should have a valid public key from he RD and the RD should have a public key for the device.
Both store these keys.
The RD thus has a list of keys for each device that registers, while the device only has one single public key to store.
4. When the device wants to communicate to another device, it queries the RD for its public key.
    1. If the peer device is registered with the same RD, the RD can simply reply itself.
    2. If the peer device is registered with another RD, it must be found first.
       See topology section.
5. The device needs to verify the certificate chain to the peer device prior to communication. 
This process is the certificate chain discovery. 
It can be combined with the previous step.
6. The devices can now communicate securely. The found public key can be stored for later use.

Public keys are exchanged and stored in the form of certificates during the process.

The RD can be implemented with RIoT OS, but it may also be just a Raspberry PI-like device running Linux.

# Implementation Thoughts

The DTLS example might serve as a basis.
The goal would be to eliminate the need of hard-coded public keys for every communication peer.
Two mechanisms would be needed to achieve that: 

- a registration mechanism to the RD, 
- a mechanism that retrieves and verifies public keys from the RD.

A means to store a once retrieved public key would also make sense. 
But there might already be such a storage in RIOTs DTLS modules.

# Topology of The Trust Network

Ideally we can support a tree-like hierarchical topology where RDs act as inner nodes (C - client device):

```
                           RD
                           |
           ... ------------+------------------------ ...
                           |
                           RD
                           |
+--------------+-----------+-------+-------- ...
|              |                   |
RD             RD                  RD
|              |                   |
+-+-+-+       ...              +-+-+-+
| | | |                        | | | |
C C C Alice                    C C C Bob
```

But it suffices to assume that an RD is connected to directly to all other existing RDs for the sake of this thesis, as in our TCoNS paper.

With the simpler topology we can only have two scenarios:

    Alice -> RD -> Bob
    Alice -> RD1 -> RD2 -> Bob

# Notes

Here I collect the notes of our meetings. - Frank

## 10 Feb 2022

- We have two phases in our process:
	- Key exchange ("key signing") between RD and clients
	- Key retrieval, i.e., a client (Alice) wants to communicate with another client (Bob) and must query the RD for Bob's public key (certificate)
		- Either the RD has Bob's key in its own database, or it should be able to ask other RDs for Bob's key.
- Key verification is an open problem
	- For the key exchange phase, we need an extensible method. Either a pre-shared keys, a "root certficate", or any other method can be used (e.g., button press as for WPS on WiFi routers).  An administrator should decide on the method to use here. We should provide an extensible interface.
	- For the key retrieval phase, the solution is more or less clear. 
	The signature of the certificate can be used as normal - Bobs key is signed by the RD, in this case, and we have the RD's key
- Keys should be identified by their common name. 
We can use either the IP address as CN, or a generic text ("Alice", "Bob"), or some UUID.
- Code should be implemented as a RIOT module to make it reusable.
