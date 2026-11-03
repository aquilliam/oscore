// Package oscore implements OSCORE, Object Security for Constrained RESTful
// Environments, defined in RFC 8613.
//
// OSCORE protects CoAP requests and responses end to end: the code, most
// options and the payload of a message are encrypted into a COSE object,
// and the result is an ordinary CoAP message that proxies can forward. The
// package works on a Message, the code, options and payload of a CoAP
// message, and leaves the transport to the application: the Token, Message
// ID and Type of the original message are copied to the protected one, over
// UDP, TCP or anything else.
//
// # Security contexts
//
// Both endpoints derive a Context from the same Master Secret and Master
// Salt, with their Sender and Recipient IDs swapped (NewContext). The
// parameters usually come from a key exchange such as EDHOC (RFC 9528),
// whose OSCORE parameters map to Config field by field, or are
// provisioned out of band.
//
// A Sender Sequence Number must never be used twice with the same keys, and
// a server must not accept a request twice. To keep a context across
// restarts, set Config.Reserve to store Sender Sequence Numbers ahead of use
// (RFC 8613, Appendix B.1.1), and either save the replay window with
// Context.ReplayWindow or set Config.ReplayWindowLost so that the server
// checks the freshness of the first request with Echo (Appendix B.1.2).
//
// # Clients
//
// A client protects a request with Context.ProtectRequest, sends the result
// with a new Token, and verifies each response with the same Token with
// Exchange.UnprotectResponse. If the server answers 4.01 (Unauthorized)
// with an Echo option, the client sends the request again with that Echo
// option added (RFC 9175).
//
// # Servers
//
// A server finds the context of a request from its kid and kid context
// with ParseRequestID, and verifies it with Context.UnprotectRequest. It
// protects each response to that request with Exchange.ProtectResponse.
// When verification fails, ErrorResponse gives the response to send.
//
// # Observe and block-wise transfers
//
// A request with an Observe option of 0 is an Observe registration, and its
// exchange protects and accepts any number of notifications in order
// (RFC 8613, Section 4.1.3.5). Block options in a message are protected like
// other options: for an end-to-end block-wise transfer, the application
// splits the message into blocks and protects each one. Outer block-wise
// transfers, between hops, happen in the transport after protection and
// before verification.
//
// # Status
//
// The package implements RFC 8613 except Appendix B.2 and the HTTP mapping
// of Section 11, with every AEAD algorithm of RFC 9053 and HKDF with SHA-256,
// SHA-384 or SHA-512. It does not implement Group OSCORE. The API may change
// before v1.0.
package oscore
