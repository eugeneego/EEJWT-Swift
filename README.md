# EEJWT

![Build](https://github.com/eugeneego/EEJWT-Swift/actions/workflows/swift.yml/badge.svg)

Lightweight JSON Web Tokens library for iOS/macOS written in Swift.

The main goal of the library to be simple as possible:

- just one small file with source code
- no external dependencies, only iOS/macOS API
- no fixed header and claims for tokens

### Suppoted JWT algorithms:

- HS256, HS384, HS512
- RS256, RS384, RS512
- PS256, PS384, PS512
- ES256, ES384, ES512

## Installation

### Swift Package Manager

Add `EEJWT` package to the dependencies in your Package.swift file.

```
.package(url: "https://github.com/eugeneego/EEJWT-Swift.git", from: "1.0.0")
```

### Manual

Just copy `Sources/EEJWT/EEJWT.swift` file to your project.

## Usage

### Signing

```swift
let jwt = JWT()

struct Header: JWTHeader {
    var typ: String?
    var alg: String = ""
}

struct Claims: Encodable {
    var iss: String?
    var sub: String?
    var aud: [String]?
    var exp: Date?
    var nbf: Date?
    var iat: Date?
    var jti: String?
}

// HMAC and dictionary payload
let algHS = JWT.Algorithm.hs256(key: Data("test".utf8))
let tokenHS = try jwt.sign(header: ["test": "Test"], claims: ["iss": "Issuer", "sub": "123"], algorithm: algHS)
print(tokenHS)

// RSA with encodable payload
let privateKeyRS =
    """
    -----BEGIN PRIVATE KEY-----
    ...private key data here...
    -----END PRIVATE KEY-----
    """
let algRS = JWT.Algorithm.rs384(privateKey: privateKeyRS, publicKey: "")
let tokenRS = try jwt.sign(header: Header(), claims: Claims(iss: "Issuer", sub: "123"), algorithm: algRS)
print(tokenRS)

// Elliptic curve with raw data payload
let privateKeyES =
    """
    -----BEGIN PRIVATE KEY-----
    ...private key data here...
    -----END PRIVATE KEY-----
    """
let algES = JWT.Algorithm.es512(privateKey: privateKeyES, publicKey: "")
let tokenES = try jwt.sign(header: Data(), claims: Data(), algorithm: algES)
print(tokenES)
```

### Verifying

```swift
let jwt = JWT()
let token = "abc.def.ghi"

// HMAC
let algHS = JWT.Algorithm.hs256(key: Data("test".utf8))
let isValidHS = jwt.verify(token: token, algorithms: [algHS])
print(isValidHS)

// RSA
let publicKeyRS =
    """
    -----BEGIN PUBLIC KEY-----
    ...public key data here...
    -----END PUBLIC KEY-----
    """
let algRS = JWT.Algorithm.rs256(privateKey: "", publicKey: publicKeyRS)
let isValidRS = jwt.verify(token: token, algorithms: [algRS])
print(isValidRS)
```

### Decoding

```swift
let jwt = JWT()
let token = "abc.def.ghi"

// As JSON data
let data = try jwt.decodeAsData(token: token)
print(data.header, data.claims)

// As JSON strings
let strings = try jwt.decodeAsString(token: token)
print(strings.header, strings.claims)

// As parsed dictionaries
let dictionaries = try jwt.decodeAsDictionary(token: token)
print(dictionaries.header, dictionaries.claims)

// As decodable objects
struct Header: Decodable { /* ... */ }
struct Claims: Decodable { /* ... */ }
let objects: (header: Header, claims: Claims) = try jwt.decodeAsObject(token: token)
print(objects.header, objects.claims)
```

## License

This library is licensed under Apache 2.0. Full license text is available in [LICENSE](https://github.com/eugeneego/EEJWT-Swift/blob/main/LICENSE).

The library uses portions of modified code for private and public keys parsing from [BlueRSA](https://github.com/Kitura/BlueRSA) and [BlueECC](https://github.com/Kitura/BlueECC).
