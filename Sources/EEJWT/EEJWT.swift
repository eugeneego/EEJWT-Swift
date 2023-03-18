//
// EEJWT
// Lightweight JSON Web Tokens library for iOS/macOS
//
// Copyright (c) 2023 Eugene Egorov.
// License: Apache License 2.0
// https://github.com/eugeneego/EEJWT-Swift/blob/main/LICENSE
//
// The library uses portions of modified code for private and public keys parsing
// from [BlueRSA](https://github.com/Kitura/BlueRSA) and [BlueECC](https://github.com/Kitura/BlueECC).
//

import Foundation
import CryptoKit

public protocol JWTAlgorithm {
    var name: String { get }

    func sign(data: Data) throws -> Data
    func verify(token: String) -> Bool
}

extension JWTAlgorithm {
    public func sign(string: String) throws -> Data {
        try sign(data: Data(string.utf8))
    }
}

public protocol JWTHeader: Encodable {
    var typ: String? { get set }
    var alg: String { get set }
}

public struct JWT {
    public init() {}

    public func sign(
        header: [String: Codable] = [:],
        claims: [String: Codable],
        algorithm: JWTAlgorithm,
        enrichHeader: Bool = true,
        encoder: JSONEncoder = JSON.defaultEncoder
    ) throws -> String {
        var header = header
        if enrichHeader {
            header["typ"] = "JWT"
        }
        header["alg"] = algorithm.name
        let headerData = try JSON.encode(dictionary: header, encoder: encoder)
        let claimsData = try JSON.encode(dictionary: claims, encoder: encoder)
        return try sign(header: headerData, claims: claimsData, algorithm: algorithm)
    }

    public func sign<Header: JWTHeader, Claims: Encodable>(
        header: Header = JSON.DefaultHeader(),
        claims: Claims,
        algorithm: JWTAlgorithm,
        enrichHeader: Bool = true,
        encoder: JSONEncoder = JSON.defaultEncoder
    ) throws -> String {
        var header = header
        if enrichHeader {
            header.typ = "JWT"
        }
        header.alg = algorithm.name
        let headerData = try encoder.encode(header)
        let claimsData = try encoder.encode(claims)
        return try sign(header: headerData, claims: claimsData, algorithm: algorithm)
    }

    public func sign(header: Data, claims: Data, algorithm: JWTAlgorithm) throws -> String {
        let headerBase64 = Base64.encode(data: header)
        let claimsBase64 = Base64.encode(data: claims)
        return try sign(headerBase64: headerBase64, claimsBase64: claimsBase64, algorithm: algorithm)
    }

    public func sign(headerBase64: String, claimsBase64: String, algorithm: JWTAlgorithm) throws -> String {
        let signingString = "\(headerBase64).\(claimsBase64)"
        let signature = try algorithm.sign(string: signingString)
        let signatureBase64 = Base64.encode(data: signature)
        return "\(signingString).\(signatureBase64)"
    }

    public func verify(token: String, algorithms: [JWTAlgorithm]) -> Bool {
        let parts = token.components(separatedBy: ".")
        guard parts.count == 3 else { return false }
        guard let headerData = Base64.decode(string: parts[0]) else { return false }
        guard let header = try? JSONDecoder().decode(JSON.DefaultHeader.self, from: headerData) else { return false }
        guard let algorithm = algorithms.first(where: { $0.name == header.alg }) else { return false }
        return algorithm.verify(token: token)
    }

    public func decodeAsData(token: String) throws -> (header: Data, claims: Data) {
        let parts = token.components(separatedBy: ".")
        guard parts.count == 3, let header = Base64.decode(string: parts[0]), let claims = Base64.decode(string: parts[1]) else {
            throw Error.invalidToken(nil)
        }
        return (header, claims)
    }

    public func decodeAsString(token: String) throws -> (header: String, claims: String) {
        let data = try decodeAsData(token: token)
        guard let header = String(data: data.header, encoding: .utf8) else { throw Error.invalidToken(nil) }
        guard let claims = String(data: data.claims, encoding: .utf8) else { throw Error.invalidToken(nil) }
        return (header, claims)
    }

    public func decodeAsDictionary(
        token: String,
        decoder: JSONDecoder = JSON.defaultDecoder
    ) throws -> (header: [String: Any], claims: [String: Any]) {
        let data = try decodeAsData(token: token)
        let header = try JSON.decode(data: data.header, decoder: decoder)
        let claims = try JSON.decode(data: data.claims, decoder: decoder)
        return (header, claims)
    }

    public func decodeAsObject<Header: Decodable, Claims: Decodable>(
        token: String,
        decoder: JSONDecoder = JSON.defaultDecoder
    ) throws -> (header: Header, claims: Claims) {
        let data = try decodeAsData(token: token)
        let header = try decoder.decode(Header.self, from: data.header)
        let claims = try decoder.decode(Claims.self, from: data.claims)
        return (header, claims)
    }
}

// MARK: - Algorithm

extension JWTAlgorithm {
    public typealias Alg = JWT.Algorithm
}

extension JWT {
    public enum Algorithm {
        public static func hs256(key: Data) -> JWTAlgorithm {
            HMACAlg(name: "HS256", key: key, signer: Digest.hmacSHA256)
        }

        public static func hs384(key: Data) -> JWTAlgorithm {
            HMACAlg(name: "HS384", key: key, signer: Digest.hmacSHA384)
        }

        public static func hs512(key: Data) -> JWTAlgorithm {
            HMACAlg(name: "HS512", key: key, signer: Digest.hmacSHA512)
        }

        public static func rs256(privateKey: String, publicKey: String) -> JWTAlgorithm {
            RSAAlg(name: "RS256", privateKey: privateKey, publicKey: publicKey, algorithm: .rsaSignatureMessagePKCS1v15SHA256)
        }

        public static func rs384(privateKey: String, publicKey: String) -> JWTAlgorithm {
            RSAAlg(name: "RS384", privateKey: privateKey, publicKey: publicKey, algorithm: .rsaSignatureMessagePKCS1v15SHA384)
        }

        public static func rs512(privateKey: String, publicKey: String) -> JWTAlgorithm {
            RSAAlg(name: "RS512", privateKey: privateKey, publicKey: publicKey, algorithm: .rsaSignatureMessagePKCS1v15SHA512)
        }

        public static func ps256(privateKey: String, publicKey: String) -> JWTAlgorithm {
            RSAAlg(name: "PS256", privateKey: privateKey, publicKey: publicKey, algorithm: .rsaSignatureMessagePSSSHA256)
        }

        public static func ps384(privateKey: String, publicKey: String) -> JWTAlgorithm {
            RSAAlg(name: "PS384", privateKey: privateKey, publicKey: publicKey, algorithm: .rsaSignatureMessagePSSSHA384)
        }

        public static func ps512(privateKey: String, publicKey: String) -> JWTAlgorithm {
            RSAAlg(name: "PS512", privateKey: privateKey, publicKey: publicKey, algorithm: .rsaSignatureMessagePSSSHA512)
        }

        public static func es256(privateKey: String, publicKey: String) -> JWTAlgorithm {
            ECAlg(name: "ES256", privateKey: privateKey, publicKey: publicKey, hash: Digest.sha256, algorithm: .ecdsaSignatureDigestX962SHA256)
        }

        public static func es384(privateKey: String, publicKey: String) -> JWTAlgorithm {
            ECAlg(name: "ES384", privateKey: privateKey, publicKey: publicKey, hash: Digest.sha384, algorithm: .ecdsaSignatureDigestX962SHA384)
        }

        public static func es512(privateKey: String, publicKey: String) -> JWTAlgorithm {
            ECAlg(name: "ES512", privateKey: privateKey, publicKey: publicKey, hash: Digest.sha512, algorithm: .ecdsaSignatureDigestX962SHA512)
        }

        struct HMACAlg: JWTAlgorithm {
            let name: String
            let key: Data
            let signer: (_ data: Data, _ key: Data) -> Data

            func sign(data: Data) throws -> Data {
                signer(data, key)
            }

            func verify(token: String) -> Bool {
                guard let parts = decompose(token: token), let signature = try? sign(data: parts.data) else { return false }
                return signature == parts.signature
            }
        }

        struct RSAAlg: JWTAlgorithm {
            let name: String
            let privateKey: String
            let publicKey: String
            let algorithm: SecKeyAlgorithm

            func sign(data: Data) throws -> Data {
                try RSA.sign(data: data, privateKey: privateKey, algorithm: algorithm)
            }

            func verify(token: String) -> Bool {
                guard let parts = decompose(token: token) else { return false }
                return RSA.verify(data: parts.data, publicKey: publicKey, signature: parts.signature, algorithm: algorithm)
            }
        }

        struct ECAlg: JWTAlgorithm {
            let name: String
            let privateKey: String
            let publicKey: String
            let hash: (_ data: Data) -> Data
            let algorithm: SecKeyAlgorithm

            func sign(data: Data) throws -> Data {
                let hash = hash(data)
                return try EllipticCurve.sign(data: hash, privateKey: privateKey, algorithm: algorithm)
            }

            func verify(token: String) -> Bool {
                guard let parts = decompose(token: token) else { return false }
                let hash = hash(parts.data)
                return EllipticCurve.verify(data: hash, publicKey: publicKey, signature: parts.signature, algorithm: algorithm)
            }
        }

        static func decompose(token: String) -> (data: Data, signature: Data)? {
            let parts = token.components(separatedBy: ".")
            guard parts.count == 3, let signature = Base64.decode(string: parts[2]) else { return nil }
            return (Data("\(parts[0]).\(parts[1])".utf8), signature)
        }
    }
}

// MARK: - JSON

extension JWT {
    public enum JSON {
        public static var defaultEncoder: JSONEncoder {
            let encoder = JSONEncoder()
            encoder.dateEncodingStrategy = .secondsSince1970
            return encoder
        }

        public static var defaultDecoder: JSONDecoder {
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .secondsSince1970
            return decoder
        }

        public struct DefaultHeader: JWTHeader, Codable {
            public var typ: String?
            public var alg: String

            public init(typ: String = "JWT", alg: String = "") {
                self.typ = typ
                self.alg = alg
            }
        }

        struct AnyCodable: Codable {
            var value: Codable

            init(value: Codable) {
                self.value = value
            }

            init(from decoder: Decoder) throws {
                let container = try decoder.singleValueContainer()
                if container.decodeNil() {
                    value = Optional<Self>.none
                    return
                }
                let types: [Codable.Type] = [Bool.self, Int.self, UInt.self, Double.self, String.self, [AnyCodable].self, [String: AnyCodable].self]
                let value = types.lazy.compactMap { type -> Codable? in try? container.decode(type) }.first
                guard let value else { throw DecodingError.dataCorruptedError(in: container, debugDescription: "AnyDecodable failed") }
                self.value = value
            }

            func encode(to encoder: Encoder) throws {
                var container = encoder.singleValueContainer()
                try container.encode(value)
            }
        }

        static func encode(dictionary: [String: Codable], encoder: JSONEncoder) throws -> Data {
            try encoder.encode(dictionary.mapValues(AnyCodable.init))
        }

        static func decode(data: Data, decoder: JSONDecoder) throws -> [String: Any] {
            let values = try decoder.decode([String: AnyCodable].self, from: data)
            return values.mapValues(mapAny)
        }

        static func mapAny(_ value: AnyCodable) -> Any {
            (value.value as? [AnyCodable])?.map(mapAny)
                ?? (value.value as? [String: AnyCodable])?.mapValues(mapAny)
                ?? value.value
        }
    }
}

// MARK: - Base64

extension JWT {
    enum Base64 {
        static func encode(data: Data) -> String {
            data.base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")
        }

        static func decode(string: String) -> Data? {
            let remainder = string.count % 4
            let paddingLength = remainder > 0 ? 4 - remainder : 0
            let base64String = string
                .replacingOccurrences(of: "-", with: "+")
                .replacingOccurrences(of: "_", with: "/")
                .padding(toLength: string.count + paddingLength, withPad: "=", startingAt: 0)
            return Data(base64Encoded: base64String)
        }
    }
}

// MARK: - Digest

extension JWT {
    enum Digest {
        static func hmacSHA256(data: Data, key: Data) -> Data {
            Data(HMAC<SHA256>.authenticationCode(for: data, using: .init(data: key)))
        }

        static func hmacSHA384(data: Data, key: Data) -> Data {
            Data(HMAC<SHA384>.authenticationCode(for: data, using: .init(data: key)))
        }

        static func hmacSHA512(data: Data, key: Data) -> Data {
            Data(HMAC<SHA512>.authenticationCode(for: data, using: .init(data: key)))
        }

        static func sha256(data: Data) -> Data {
            Data(SHA256.hash(data: data))
        }

        static func sha384(data: Data) -> Data {
            Data(SHA384.hash(data: data))
        }

        static func sha512(data: Data) -> Data {
            Data(SHA512.hash(data: data))
        }
    }
}

// MARK: - RSA

extension JWT {
    enum RSA {
        static func sign(data: Data, privateKey: String, algorithm: SecKeyAlgorithm) throws -> Data {
            let key = try key(string: privateKey, isPrivate: true)
            return try Signature.sign(data: data, privateKey: key, algorithm: algorithm)
        }

        static func verify(data: Data, publicKey: String, signature: Data, algorithm: SecKeyAlgorithm) -> Bool {
            guard let key = try? key(string: publicKey, isPrivate: false) else { return false }
            return Signature.verify(data: data, publicKey: key, signature: signature, algorithm: algorithm)
        }

        static func key(string: String, isPrivate: Bool) throws -> SecKey {
            let parts = string.filter { !" \n\r\t".contains($0) }.components(separatedBy: "-----")
            guard parts.count >= 5 else { throw Error.invalidKey(nil) }
            let keyString = parts[2]
            guard let data = Data(base64Encoded: keyString) else { throw Error.invalidKey(nil) }
            return try key(data: data, isPrivate: isPrivate)
        }

        static func key(data: Data, isPrivate: Bool) throws -> SecKey {
            let data = try removeX509Header(keyData: data)
            let keyClass = isPrivate ? kSecAttrKeyClassPrivate : kSecAttrKeyClassPublic
            let attributes = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeyClass: keyClass] as CFDictionary
            return try Signature.key(data: data, attributes: attributes)
        }

        static func removeX509Header(keyData: Data) throws -> Data {
            guard !keyData.isEmpty else { throw Error.invalidKey(nil) }
            if keyData.count > 26 && keyData[26] == 0x30 {
                return keyData.advanced(by: 26)
            }
            var index = 0
            guard keyData[index] == 0x30 else { throw Error.invalidKey(nil) }
            index += 1
            index += keyData[index] > 0x80 ? Int(keyData[index]) - 0x80 + 1 : 1
            if keyData[index] == 0x02 {
                return keyData
            }
            guard keyData[index] == 0x30 else { throw Error.invalidKey(nil) }
            index += 15
            guard keyData[index] == 0x03 else { throw Error.invalidKey(nil) }
            index += 1
            index += keyData[index] > 0x80 ? Int(keyData[index]) - 0x80 + 1 : 1
            guard keyData[index] == 0 else { throw Error.invalidKey(nil) }
            index += 1
            let data = keyData.subdata(in: index ..< keyData.count)
            return data
        }
    }
}

// MARK: - Elliptic Curve

extension JWT {
    enum EllipticCurve {
        static func sign(data: Data, privateKey: String, algorithm: SecKeyAlgorithm) throws -> Data {
            let key = try Self.privateKey(string: privateKey)
            let asn1Signature = try Signature.sign(data: data, privateKey: key, algorithm: algorithm)
            let signature = try asn1ToSig(asn1: asn1Signature)
            return signature.r + signature.s
        }

        static func verify(data: Data, publicKey: String, signature: Data, algorithm: SecKeyAlgorithm) -> Bool {
            let r = signature.subdata(in: 0 ..< signature.count / 2)
            let s = signature.subdata(in: signature.count / 2 ..< signature.count)
            guard let asn1Signature = try? sigToAsn1(r: r, s: s) else { return false }
            guard let key = try? Self.publicKey(string: publicKey) else { return false }
            return Signature.verify(data: data, publicKey: key, signature: asn1Signature, algorithm: algorithm)
        }

        static func privateKey(string: String) throws -> SecKey {
            var parts = string.filter { !" \n\r\t".contains($0) }.components(separatedBy: "-----")
            guard parts.count >= 5 else { throw Error.invalidKey(nil) }
            if parts[1] == "BEGINECPARAMETERS" {
                parts.removeFirst(5)
                guard parts.count >= 5 else { throw Error.invalidKey(nil) }
            }
            guard let data = Data(base64Encoded: parts[2]) else { throw Error.invalidKey(nil) }
            if parts[1] == "BEGINECPRIVATEKEY" {
                return try privateKey(sec1: data)
            } else if parts[1] == "BEGINPRIVATEKEY" {
                return try privateKey(pkcs8: data)
            } else {
                throw Error.invalidKey(nil)
            }
        }

        static func publicKey(string: String) throws -> SecKey {
            let parts = string.filter { !" \n\r\t".contains($0) }.components(separatedBy: "-----")
            guard parts.count >= 5 else { throw Error.invalidKey(nil) }
            guard let data = Data(base64Encoded: parts[2]) else { throw Error.invalidKey(nil) }
            guard parts[1] == "BEGINPUBLICKEY" else { throw Error.invalidKey(nil) }
            return try publicKey(der: data)
        }

        static func privateKey(sec1: Data) throws -> SecKey {
            let (element, _) = ASN1.readElement(sec1)
            guard
                case .sequence(elements: let sequence) = element,
                sequence.count >= 4,
                case .bytes(let privateKeyData) = sequence[1],
                case .constructed(_, .bytes(let publicKeyData)) = sequence[3]
            else { throw Error.invalidKey(nil) }
            let trimmedPublicKeyData = publicKeyData.drop { $0 == 0x00 }
            return try privateKey(privateKeyData: privateKeyData, publicKeyData: trimmedPublicKeyData)
        }

        static func privateKey(pkcs8: Data) throws -> SecKey {
            let (result, _) = ASN1.readElement(pkcs8)
            guard
                case .sequence(let sequence) = result,
                sequence.count >= 3,
                case .bytes(let privateOctets) = sequence[2]
            else { throw Error.invalidKey(nil) }
            let (octets, _) = ASN1.readElement(privateOctets)
            guard
                case .sequence(let sequence) = octets,
                sequence.count >= 3,
                case .bytes(let privateKeyData) = sequence[1]
            else { throw Error.invalidKey(nil) }
            let publicKeyData: Data
            if case .constructed(1, .bytes(let data)) = sequence[2] {
                publicKeyData = data
            } else if sequence.count >= 4, case .constructed(1, .bytes(let data)) = sequence[3] {
                publicKeyData = data
            } else {
                throw Error.invalidKey(nil)
            }
            let trimmedPublicKeyData = publicKeyData.drop { $0 == 0x00 }
            return try privateKey(privateKeyData: privateKeyData, publicKeyData: trimmedPublicKeyData)
        }

        static func privateKey(privateKeyData: Data, publicKeyData: Data) throws -> SecKey {
            let data = publicKeyData + privateKeyData
            let attributes = [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass: kSecAttrKeyClassPrivate] as CFDictionary
            return try Signature.key(data: data, attributes: attributes)
        }

        static func publicKey(der: Data) throws -> SecKey {
            let (element, _) = ASN1.readElement(der)
            guard
                case .sequence(let sequence) = element,
                sequence.count >= 2,
                case .bytes(let publicKeyData) = sequence[1]
            else { throw Error.invalidKey(nil) }
            let data = publicKeyData.drop { $0 == 0x00 }
            let attributes = [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass: kSecAttrKeyClassPublic] as CFDictionary
            return try Signature.key(data: data, attributes: attributes)
        }

        static func sigToAsn1(r: Data, s: Data) throws -> Data {
            guard r.count == s.count, r.count == 32 || r.count == 48 || r.count == 66 else { throw Error.signatureFailed(nil) }
            let prepare = { (data: Data) -> Data in
                // if first bit is 1, add a 00 byte to mark it as positive for ASN1
                var data = data
                if data[0] == 0 { data = data.advanced(by: 1) }
                if data[0].leadingZeroBitCount == 0 { data = Data(count: 1) + data }
                return data
            }
            let (rSig, sSig) = (prepare(r), prepare(s))
            let (rLength, sLength) = (UInt8(rSig.count), UInt8(sSig.count))
            let length = rLength + sLength + 4
            var asn1 = Data()
            asn1 += length > 127 ? [0x30, 0x81, length] : [0x30, length]
            asn1 += [0x02, rLength] + rSig
            asn1 += [0x02, sLength] + sSig
            return asn1
        }

        static func asn1ToSig(asn1: Data) throws -> (r: Data, s: Data) {
            let length = asn1.count < 96 ? 64 : asn1.count < 132 ? 96 : 132
            let (asn1Sig, _) = ASN1.readElement(asn1)
            guard
                case .sequence(let sequence) = asn1Sig,
                sequence.count >= 2,
                case .integer(let r) = sequence[0],
                case .integer(let s) = sequence[1]
            else { throw Error.signatureFailed(nil) }
            let trim = { (data: Data) -> Data in
                // ASN1 adds 00 bytes in front of negative Int to mark it as positive, these must be removed to make a valid EC signature
                let extra = data.count - length / 2
                return extra < 0 ? Data(count: 1) + data : data.dropFirst(extra)
            }
            return (trim(r), trim(s))
        }
    }
}

// MARK: - Signature

extension JWT {
    enum Signature {
        static func sign(data: Data, privateKey: SecKey, algorithm: SecKeyAlgorithm) throws -> Data {
            var error: Unmanaged<CFError>?
            guard let signature = SecKeyCreateSignature(privateKey, algorithm, data as CFData, &error) else {
                throw Error.signatureFailed(error?.takeRetainedValue())
            }
            return signature as Data
        }

        static func verify(data: Data, publicKey: SecKey, signature: Data, algorithm: SecKeyAlgorithm) -> Bool {
            var error: Unmanaged<CFError>?
            let result = SecKeyVerifySignature(publicKey, algorithm, data as CFData, signature as CFData, &error)
            return result
        }

        static func key(data: Data, attributes: CFDictionary) throws -> SecKey {
            var error: Unmanaged<CFError>?
            guard let key = SecKeyCreateWithData(data as CFData, attributes, &error) else {
                throw Error.invalidKey(error?.takeRetainedValue())
            }
            return key
        }
    }
}

// MARK: - ASN1 DER

extension JWT {
    struct ASN1 {
        indirect enum ASN1Element {
            case sequence([ASN1Element])
            case integer(Data)
            case bytes(Data)
            case constructed(tag: Int, ASN1Element)
            case unknown
        }

        static func readElement(_ data: Data) -> (ASN1Element, Int) {
            guard data.count >= 2 else { return (.unknown, data.count) }
            switch data[0] {
            case 0x30, 0x31: // sequence, set
                let l = readLength(data.advanced(by: 1))
                var result: [ASN1Element] = []
                var subdata = data.advanced(by: l.start)
                var bytesRead = 0
                while bytesRead < l.length {
                    let (element, length) = readElement(subdata)
                    result += [element]
                    subdata = subdata.count > length ? subdata.advanced(by: length) : Data()
                    bytesRead += length
                }
                return (.sequence(result), l.end)
            case 0x02: // integer
                let l = readLength(data.advanced(by: 1))
                return (.integer(data.subdata(in: l.start ..< l.end)), l.end)
            case let s where (s & 0xe0) == 0xa0: // constructed
                let l = readLength(data.advanced(by: 1))
                let subdata = data.advanced(by: l.start)
                let (element, _) = readElement(subdata)
                return (.constructed(tag: Int(s & 0x1f), element), l.end)
            default: // octet string
                let l = readLength(data.advanced(by: 1))
                return (.bytes(data.subdata(in: l.start ..< l.end)), l.end)
            }
        }

        static func readLength(_ data: Data) -> (length: Int, lengthOfLength: Int, start: Int, end: Int) {
            if data[0] & 0x80 == 0x00 { // short form
                let length = Int(data[0])
                return (length, 1, 1 + 1, 1 + 1 + length)
            } else {
                let lengthOfLength = Int(data[0] & 0x7F)
                let length = readInt(data.subdata(in: 1 ..< (1 + lengthOfLength)))
                return (length, 1 + lengthOfLength, 1 + 1 + lengthOfLength, 1 + 1 + lengthOfLength + length)
            }
        }

        static func readInt(_ data: Data) -> Int {
            data.reduce(0) { 256 * $0 + Int($1) }
        }
    }
}

// MARK: - Error

extension JWT {
    public enum Error: Swift.Error {
        case invalidToken(Swift.Error?)
        case invalidKey(Swift.Error?)
        case signatureFailed(Swift.Error?)
    }
}
