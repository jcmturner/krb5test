# krb5test

This project provides a mock Kerberos Domain Controller (KDC) suitable for testing.

The mock KDC does not provide all KDC funcationality but it does cover the basics of:
* Responding to the initial login to obtain a TGT via an AS exchange
* Granting a service ticket in response to a TGS exchange

## Usage
1. Create a logger that the KDC will log to:
```go
l := log.New(os.Stderr, "KDC Test Server: ", log.LstdFlags)
```
2. Create a map of principals (both user and service principals). 
The keys of the map are the principal names and the values are the groups each is a member of.
```go
p := make(map[string][]string)
p["testuser1"] = []string{"testgroup1"}
p["HTTP/host.test.realm.com"] = []string{}
```
3. Create the KDC test instance:
```go
kdc, err := NewKDC(p, l)
```
4. Start the KDC server and defer its closure:
```go
kdc.Start()
defer kdc.Close()
```

The KDC dynamically creates credentials for the principals specified.
These can be accessed in the form of a keytab from the KDC:
```go
kdc.Keytab
```

A krb5.conf that can be used for a client can also be obtained from the KDC instance:
```go
kdc.KRB5Conf
```
The KDC instance will dynamically pick available ports to use on localhost.
Use of this krb5.conf will automatically wire up any client to use this connection.

The Realm name used is also available from the KDC instance:
```go
kdc.Realm
```