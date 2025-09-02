# Internal Pharia Rust SDK

## About

With a growing number of different teams at Pharia utilizing Rust we find that the same problems are solved repeatedly. The current trigger for creatingn this library is implementing authorization against our IAM for yet another service.

This project in no way aims to take the autonomy over their SDKs and clients away from the individual teams. If e.g. IAM/OS would offer a Rust client library we are happy to just import it. In lack, of support, we try to unify the effort here.

This effort aims to both encapsualte knowledge about our artefacts, as well as conventions in Aleph Alpha in general as well as Rust artefacts in particular.
