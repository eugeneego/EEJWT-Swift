import XCTest
@testable import EEJWT

final class EEJWTTests: XCTestCase {
    // Using https://jwt.io/ and https://token.dev/ for reference tokens

    struct Header: JWTHeader, Codable, Equatable {
        var typ: String?
        var alg: String = ""
    }

    struct Claims: Codable, Equatable {
        var sub: String?
        var name: String?
        var admin: Bool?
        var iat: Date?
        var exp: Date?
    }

    let jwt: JWT = JWT()

    // MARK: - Decoding

    func testDecodeStrings() throws {
        let strings = try jwt.decodeAsString(token: Constants.hs256Token)
        XCTAssert(strings.header == Constants.hs256Header, "Header should be equal to reference header")
        XCTAssert(strings.claims == Constants.refClaims, "Claims should be equal to reference claims")
    }

    func testDecodeObjects() throws {
        let objects: (header: Header, claims: Claims) = try jwt.decodeAsObject(token: Constants.hs256Token)
        let refHeader = Header(typ: "JWT", alg: "HS256")
        XCTAssert(objects.header == refHeader, "Header should be equal to reference header")
        XCTAssert(objects.claims == Constants.claims, "Claims should be equal to reference claims")
    }

    // MARK: - HS256

    func testHS256Verify() throws {
        let isValid = jwt.verify(token: Constants.hs256Token, algorithms: [Constants.hs256Alg])
        XCTAssert(isValid, "Reference token should be valid")
    }

    func testHS256Sign() throws {
        // using same payload as reference token to check signature
        let token = try jwt.sign(header: Data(Constants.hs256Header.utf8), claims: Data(Constants.refClaims.utf8), algorithm: Constants.hs256Alg)
        XCTAssert(token == Constants.hs256Token, "Token should be equal to reference token")
    }

    func testHS256SignAndVerifyObjects() throws {
        let token = try jwt.sign(header: Constants.header, claims: Constants.claims, algorithm: Constants.hs256Alg)
        let isValid = jwt.verify(token: token, algorithms: [Constants.hs256Alg])
        XCTAssert(isValid, "Generated token should be valid")
    }

    // MARK: - HS384

    func testHS384Verify() throws {
        let isValid = jwt.verify(token: Constants.hs384Token, algorithms: [Constants.hs384Alg])
        XCTAssert(isValid, "Reference token should be valid")
    }

    func testHS384Sign() throws {
        // using same payload as reference token to check signature
        let token = try jwt.sign(header: Data(Constants.hs384Header.utf8), claims: Data(Constants.refClaims.utf8), algorithm: Constants.hs384Alg)
        XCTAssert(token == Constants.hs384Token, "Token should be equal to reference token")
    }

    func testHS384SignAndVerifyObjects() throws {
        let token = try jwt.sign(header: Constants.header, claims: Constants.claims, algorithm: Constants.hs384Alg)
        let isValid = jwt.verify(token: token, algorithms: [Constants.hs384Alg])
        XCTAssert(isValid, "Generated token should be valid")
    }

    // MARK: - HS512

    func testHS512Verify() throws {
        let isValid = jwt.verify(token: Constants.hs512Token, algorithms: [Constants.hs512Alg])
        XCTAssert(isValid, "Reference token should be valid")
    }

    func testHS512Sign() throws {
        // using same payload as reference token to check signature
        let token = try jwt.sign(header: Data(Constants.hs512Header.utf8), claims: Data(Constants.refClaims.utf8), algorithm: Constants.hs512Alg)
        XCTAssert(token == Constants.hs512Token, "Token should be equal to reference token")
    }

    func testHS512SignAndVerifyObjects() throws {
        let token = try jwt.sign(header: Constants.header, claims: Constants.claims, algorithm: Constants.hs512Alg)
        let isValid = jwt.verify(token: token, algorithms: [Constants.hs512Alg])
        XCTAssert(isValid, "Generated token should be valid")
    }

    // MARK: - RS256

    func testRS256Verify() throws {
        let isValid = jwt.verify(token: Constants.rs256Token, algorithms: [Constants.rs256Alg])
        XCTAssert(isValid, "Reference token should be valid")
    }

    func testRS256Sign() throws {
        // using same payload as reference token to check signature
        let token = try jwt.sign(header: Data(Constants.rs256Header.utf8), claims: Data(Constants.refClaims.utf8), algorithm: Constants.rs256Alg)
        XCTAssert(token == Constants.rs256Token, "Token should be equal to reference token")
    }

    func testRS256SignAndVerifyObjects() throws {
        let token = try jwt.sign(header: Constants.header, claims: Constants.claims, algorithm: Constants.rs256Alg)
        let isValid = jwt.verify(token: token, algorithms: [Constants.rs256Alg])
        XCTAssert(isValid, "Generated token should be valid")
    }

    // MARK: - RS384

    func testRS384Verify() throws {
        let isValid = jwt.verify(token: Constants.rs384Token, algorithms: [Constants.rs384Alg])
        XCTAssert(isValid, "Reference token should be valid")
    }

    func testRS384Sign() throws {
        // using same payload as reference token to check signature
        let token = try jwt.sign(header: Data(Constants.rs384Header.utf8), claims: Data(Constants.refClaims.utf8), algorithm: Constants.rs384Alg)
        XCTAssert(token == Constants.rs384Token, "Token should be equal to reference token")
    }

    func testRS384SignAndVerifyObjects() throws {
        let token = try jwt.sign(header: Constants.header, claims: Constants.claims, algorithm: Constants.rs384Alg)
        let isValid = jwt.verify(token: token, algorithms: [Constants.rs384Alg])
        XCTAssert(isValid, "Generated token should be valid")
    }

    // MARK: - RS512

    func testRS512Verify() throws {
        let isValid = jwt.verify(token: Constants.rs512Token, algorithms: [Constants.rs512Alg])
        XCTAssert(isValid, "Reference token should be valid")
    }

    func testRS512Sign() throws {
        // using same payload as reference token to check signature
        let token = try jwt.sign(header: Data(Constants.rs512Header.utf8), claims: Data(Constants.refClaims.utf8), algorithm: Constants.rs512Alg)
        XCTAssert(token == Constants.rs512Token, "Token should be equal to reference token")
    }

    func testRS512SignAndVerifyObjects() throws {
        let token = try jwt.sign(header: Constants.header, claims: Constants.claims, algorithm: Constants.rs512Alg)
        let isValid = jwt.verify(token: token, algorithms: [Constants.rs512Alg])
        XCTAssert(isValid, "Generated token should be valid")
    }

    // MARK: - ES256

    func testES256Verify() throws {
        let isValid = jwt.verify(token: Constants.es256Token, algorithms: [Constants.es256Alg])
        XCTAssert(isValid, "Reference token should be valid")
    }

    func testES256SignAndVerifyObjects() throws {
        let token = try jwt.sign(header: Constants.header, claims: Constants.claims, algorithm: Constants.es256Alg)
        let isValid = jwt.verify(token: token, algorithms: [Constants.es256Alg])
        XCTAssert(isValid, "Generated token should be valid")
    }

    // MARK: - ES384

    func testES384Verify() throws {
        let isValid = jwt.verify(token: Constants.es384Token, algorithms: [Constants.es384Alg])
        XCTAssert(isValid, "Reference token should be valid")
    }

    func testES384SignAndVerifyObjects() throws {
        let token = try jwt.sign(header: Constants.header, claims: Constants.claims, algorithm: Constants.es384Alg)
        let isValid = jwt.verify(token: token, algorithms: [Constants.es384Alg])
        XCTAssert(isValid, "Generated token should be valid")
    }

    // MARK: - ES512

    func testES512Verify() throws {
        let isValid = jwt.verify(token: Constants.es512Token, algorithms: [Constants.es512Alg])
        XCTAssert(isValid, "Reference token should be valid")
    }

    func testES512SignAndVerifyObjects() throws {
        let token = try jwt.sign(header: Constants.header, claims: Constants.claims, algorithm: Constants.es512Alg)
        let isValid = jwt.verify(token: token, algorithms: [Constants.es512Alg])
        XCTAssert(isValid, "Generated token should be valid")
    }

    // MARK: - Constants

    enum Constants {
        static let header: Header = Header()

        static let claims: Claims = Claims(
            sub: "1234567890",
            name: "John Doe",
            admin: true,
            iat: Date(timeIntervalSince1970: 1679131449),
            exp: Date(timeIntervalSince1970: 1679135049)
        )

        static let refClaims: String = "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"admin\":true,\"iat\":1679131449,\"exp\":1679135049}"

        static let hsKey: String = "testkey"
        static let hs256Alg: JWTAlgorithm = JWT.Algorithm.hs256(key: Data(hsKey.utf8))
        static let hs384Alg: JWTAlgorithm = JWT.Algorithm.hs384(key: Data(hsKey.utf8))
        static let hs512Alg: JWTAlgorithm = JWT.Algorithm.hs512(key: Data(hsKey.utf8))
        static let hs256Header: String = "{\"typ\":\"JWT\",\"alg\":\"HS256\"}"
        static let hs384Header: String = "{\"typ\":\"JWT\",\"alg\":\"HS384\"}"
        static let hs512Header: String = "{\"typ\":\"JWT\",\"alg\":\"HS512\"}"
        // swiftlint:disable:next line_length
        static let hs256Token: String = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTY3OTEzMTQ0OSwiZXhwIjoxNjc5MTM1MDQ5fQ.gfp2DEqbI6uY2jNtsqpwqPvy-jXphd7Eoc2q8SIaK_0"
        // swiftlint:disable:next line_length
        static let hs384Token: String = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTY3OTEzMTQ0OSwiZXhwIjoxNjc5MTM1MDQ5fQ.UBtVvSu90Q5SW3fBtp4Hq37jbJxJUZOczo4aX4TdF3GbS1Dgvj-Tz1z1V4ykXeaN"
        // swiftlint:disable:next line_length
        static let hs512Token: String = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTY3OTEzMTQ0OSwiZXhwIjoxNjc5MTM1MDQ5fQ.NyazU_msh01GwuDzb_pEi16ZWl_OLJvBfSRTYzhX5Pm2OiO3-7C4GKvO7tG9mxkEQsrVN3ajnANK7NL4uMbH8w"

        static let rsPublicKey: String =
            """
            -----BEGIN PUBLIC KEY-----
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6S7asUuzq5Q/3U9rbs+P
            kDVIdjgmtgWreG5qWPsC9xXZKiMV1AiV9LXyqQsAYpCqEDM3XbfmZqGb48yLhb/X
            qZaKgSYaC/h2DjM7lgrIQAp9902Rr8fUmLN2ivr5tnLxUUOnMOc2SQtr9dgzTONY
            W5Zu3PwyvAWk5D6ueIUhLtYzpcB+etoNdL3Ir2746KIy/VUsDwAM7dhrqSK8U2xF
            CGlau4ikOTtvzDownAMHMrfE7q1B6WZQDAQlBmxRQsyKln5DIsKv6xauNsHRgBAK
            ctUxZG8M4QJIx3S6Aughd3RZC4Ca5Ae9fd8L8mlNYBCrQhOZ7dS0f4at4arlLcaj
            twIDAQAB
            -----END PUBLIC KEY-----
            """
        static let rsPrivateKey: String =
            """
            -----BEGIN PRIVATE KEY-----
            MIIEwAIBADANBgkqhkiG9w0BAQEFAASCBKowggSmAgEAAoIBAQDpLtqxS7OrlD/d
            T2tuz4+QNUh2OCa2Bat4bmpY+wL3FdkqIxXUCJX0tfKpCwBikKoQMzddt+ZmoZvj
            zIuFv9eploqBJhoL+HYOMzuWCshACn33TZGvx9SYs3aK+vm2cvFRQ6cw5zZJC2v1
            2DNM41hblm7c/DK8BaTkPq54hSEu1jOlwH562g10vcivbvjoojL9VSwPAAzt2Gup
            IrxTbEUIaVq7iKQ5O2/MOjCcAwcyt8TurUHpZlAMBCUGbFFCzIqWfkMiwq/rFq42
            wdGAEApy1TFkbwzhAkjHdLoC6CF3dFkLgJrkB7193wvyaU1gEKtCE5nt1LR/hq3h
            quUtxqO3AgMBAAECggEBANX6C+7EA/TADrbcCT7fMuNnMb5iGovPuiDCWc6bUIZC
            Q0yac45l7o1nZWzfzpOkIprJFNZoSgIF7NJmQeYTPCjAHwsSVraDYnn3Y4d1D3tM
            5XjJcpX2bs1NactxMTLOWUl0JnkGwtbWp1Qq+DBnMw6ghc09lKTbHQvhxSKNL/0U
            C+YmCYT5ODmxzLBwkzN5RhxQZNqol/4LYVdji9bS7N/UITw5E6LGDOo/hZHWqJsE
            fgrJTPsuCyrYlwrNkgmV2KpRrGz5MpcRM7XHgnqVym+HyD/r9E7MEFdTLEaiiHcm
            Ish1usJDEJMFIWkF+rnEoJkQHbqiKlQBcoqSbCmoMWECgYEA/4379mMPF0JJ/EER
            4VH7/ZYxjdyphenx2VYCWY/uzT0KbCWQF8KXckuoFrHAIP3EuFn6JNoIbja0NbhI
            HGrU29BZkATG8h/xjFy/zPBauxTQmM+yS2T37XtMoXNZNS/ubz2lJXMOapQQiXVR
            l/tzzpyWaCe9j0NT7DAU0ZFmDbECgYEA6ZbjkcOs2jwHsOwwfamFm4VpUFxYtED7
            9vKzq5d7+Ii1kPKHj5fDnYkZd+mNwNZ02O6OGxh40EDML+i6nOABPg/FmXeVCya9
            Vump2Yqr2fAK3xm6QY5KxAjWWq2kVqmdRmICSL2Z9rBzpXmD5o06y9viOwd2bhBo
            0wB02416GecCgYEA+S/ZoEa3UFazDeXlKXBn5r2tVEb2hj24NdRINkzC7h23K/z0
            pDZ6tlhPbtGkJodMavZRk92GmvF8h2VJ62vAYxamPmhqFW5Qei12WL+FuSZywI7F
            q/6oQkkYT9XKBrLWLGJPxlSKmiIGfgKHrUrjgXPutWEK1ccw7f10T2UXvgECgYEA
            nXqLa58G7o4gBUgGnQFnwOSdjn7jkoppFCClvp4/BtxrxA+uEsGXMKLYV75OQd6T
            IhkaFuxVrtiwj/APt2lRjRym9ALpqX3xkiGvz6ismR46xhQbPM0IXMc0dCeyrnZl
            QKkcrxucK/Lj1IBqy0kVhZB1IaSzVBqeAPrCza3AzqsCgYEAvSiEjDvGLIlqoSvK
            MHEVe8PBGOZYLcAdq4YiOIBgddoYyRsq5bzHtTQFgYQVK99Cnxo+PQAvzGb+dpjN
            /LIEAS2LuuWHGtOrZlwef8ZpCQgrtmp/phXfVi6llcZx4mMm7zYmGhh2AsA9yEQc
            acgc4kgDThAjD7VlXad9UHpNMO8=
            -----END PRIVATE KEY-----
            """
        static let rs256Alg: JWTAlgorithm = JWT.Algorithm.rs256(privateKey: rsPrivateKey, publicKey: rsPublicKey)
        static let rs384Alg: JWTAlgorithm = JWT.Algorithm.rs384(privateKey: rsPrivateKey, publicKey: rsPublicKey)
        static let rs512Alg: JWTAlgorithm = JWT.Algorithm.rs512(privateKey: rsPrivateKey, publicKey: rsPublicKey)
        static let rs256Header: String = "{\"typ\":\"JWT\",\"alg\":\"RS256\"}"
        static let rs384Header: String = "{\"typ\":\"JWT\",\"alg\":\"RS384\"}"
        static let rs512Header: String = "{\"typ\":\"JWT\",\"alg\":\"RS512\"}"
        // swiftlint:disable:next line_length
        static let rs256Token: String = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTY3OTEzMTQ0OSwiZXhwIjoxNjc5MTM1MDQ5fQ.v3UDRN5pz2NwFNsoC-rfZJkRzl1dnfVXf9CJCQwQjS_q3RZ2O53XtLl6uXRtM_4XIo-U6i8WUGyrD8XrFdIxMB05T4HBiWMIa02l6u9dE9LdXKiHXCNuccxGHRVQ8MpN31DNjAdANBKVx59A1CdJ2opRuNXjq2P6W_JUM2aXzD9msfatFcToN0HKQoPQrQjadQyu8MYqP8ntjdIkCujAFz-nDsjNMIE4Omr-nq9-GRoLXkyVEicdwGg6qnxR5ylhofftPs04bpq1omt7gxtFqnmQTR5v7xLQ2ChyG8kHC2zx0ySPoZ5720xnPZEn_K6rj3RE0xLsGevhGiVS9TWjJw"
        // swiftlint:disable:next line_length
        static let rs384Token: String = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzM4NCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTY3OTEzMTQ0OSwiZXhwIjoxNjc5MTM1MDQ5fQ.E3lZXPphgBdzmw_VMrARPbfOwapNS1nTRbCm1JbIbheAZQW9pjTd6su_Wf17QoM-U59FLXJc5pZjmwlL5oUUGvt9-JZryyboQm39CvM4jtOVguNxXpUnJrSz2YxX89qCat8MnWbhLYEAPJBH9jy4RDvDaC_wGTanIp12iLDfY7cAwv-GWEfl5ThGdtAOm2v7oKVDfAWFnev2WRdESAwSZ2Y3WTY_4p-lVqNPOdnE0OnTrzwIX1gpjbdJZq6oRUtSepZB4tOM0_WmyHfKxsrykkXxO5X_ZrQqkcHNii9KGyv494n-sJjHCwqfvy1rRfObqOa5HgPsYqPFyTPVP9EoKQ"
        // swiftlint:disable:next line_length
        static let rs512Token: String = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTY3OTEzMTQ0OSwiZXhwIjoxNjc5MTM1MDQ5fQ.bKsleqbx-f_GJ6H564ShdjPA2AmMa9dco9tRQTBVy_w-543IpJWj9sjeiGKQ9prN5_LQfOiSbWzwhJiChRfsPeXXu7KOt0Ksxb-XhFD-AujvRcfMylRUI4kHFoYiUEqA9R-xwFJaJ-PRtHRjUWzOqQQO-CwM6whDIJu2QDwQtnfSAim2dEtQmaNjCo9YA6Z4oU1EXgqOykAx19FXmUR9S9fD2L0vvm73uawWnrszBXKHYRg2SiI0h3k3enUpljibusa9ZwQyNY9Rv0SNz5wNUL_vaVyfDLfXug6jzJQc6Z-CcYLq_Bv-OBUq77-8q7qDlDv4Xzvp_W1uRDr7CjC7IQ"

        static let es256PublicKey: String =
            """
            -----BEGIN PUBLIC KEY-----
            MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERqVXn+o+6zEOpWEsGw5CsB+wd8zO
            jxu0uASGpiGP+wYfcc1unyMxcStbDzUjRuObY8DalaCJ9/J6UrkQkZBtZw==
            -----END PUBLIC KEY-----
            """
        static let es256PrivateKey: String =
            """
            -----BEGIN PRIVATE KEY-----
            MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQglBnO+qn+RecAQ31T
            jBklNu+AwiFN5eVHBFbnjecmMryhRANCAARGpVef6j7rMQ6lYSwbDkKwH7B3zM6P
            G7S4BIamIY/7Bh9xzW6fIzFxK1sPNSNG45tjwNqVoIn38npSuRCRkG1n
            -----END PRIVATE KEY-----
            """
        static let es256Alg: JWTAlgorithm = JWT.Algorithm.es256(privateKey: es256PrivateKey, publicKey: es256PublicKey)
        // swiftlint:disable:next line_length
        static let es256Token: String = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTY3OTEzMTQ0OSwiZXhwIjoxNjc5MTM1MDQ5fQ.G5lwx_uzfYjXvd9FieF5ThXxmjnGak9ic1r6HJwZFpRxUj6S20Z8-5RSV-pUYRivCIYTlQOP8xw5FvASuAooEg"

        static let es384PublicKey: String =
            """
            -----BEGIN PUBLIC KEY-----
            MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAElS+JW3VaBvVr9GKZGn1399WDTd61Q9fw
            QMmZuBGAYPdl/rWk705QY6WhlmbokmEVva/mEHSoNQ98wFm9FBCqzh45IGd/DGwZ
            04Xhi5ah+1bKbkVhtds8nZtHRdSJokYp
            -----END PUBLIC KEY-----
            """
        static let es384PrivateKey: String =
            """
            -----BEGIN PRIVATE KEY-----
            MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDAa57e0Q/KAqmIVOVcW
            X7b+Sm5YVNRUx8W7nc4wk1IBj2QJmsj+MeShQRHG4ozTE9KhZANiAASVL4lbdVoG
            9Wv0YpkafXf31YNN3rVD1/BAyZm4EYBg92X+taTvTlBjpaGWZuiSYRW9r+YQdKg1
            D3zAWb0UEKrOHjkgZ38MbBnTheGLlqH7VspuRWG12zydm0dF1ImiRik=
            -----END PRIVATE KEY-----
            """
        static let es384Alg: JWTAlgorithm = JWT.Algorithm.es384(privateKey: es384PrivateKey, publicKey: es384PublicKey)
        // swiftlint:disable:next line_length
        static let es384Token: String = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTY3OTEzMTQ0OSwiZXhwIjoxNjc5MTM1MDQ5fQ.NilMleffwmVOohKIvWcdxYUoh0arwapgIvckQ13Vsa8V1RIXM6IxXr9k7oe-0U3wb9-5YFZkYwOulnmhZUJgBtdEAq7ZcVZtHMF8aW7OMhXJGA-1wpBpfjkftsP9PQNk"

        static let es512PublicKey: String =
            """
            -----BEGIN PUBLIC KEY-----
            MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBh4Cv4rcExpKWeuOazO4l05gGy0Yl
            /SK0zZNMbCxo7T5wZxeivx/Qs9dsH0H+AsrubS2HeiRfPKkiur6qBMywyKAAYt2/
            3ZoBGbp597+wQnJEn6fggHGExFObrAh7wBmGWR0tbHMTJ+6yJctkeifU2C39Dx38
            9hZitslVZLtWucrTlsk=
            -----END PUBLIC KEY-----
            """
        static let es512PrivateKey: String =
            """
            -----BEGIN PRIVATE KEY-----
            MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBFR87FuPU7Ic0Yrl3
            H7CpJEe2vaXPjbfzKCgg3kl8mfsSv/KT8osWezIzM/OehSiv0uaDSn5d4iPRd9MM
            bQeJnp+hgYkDgYYABAGHgK/itwTGkpZ645rM7iXTmAbLRiX9IrTNk0xsLGjtPnBn
            F6K/H9Cz12wfQf4Cyu5tLYd6JF88qSK6vqoEzLDIoABi3b/dmgEZunn3v7BCckSf
            p+CAcYTEU5usCHvAGYZZHS1scxMn7rIly2R6J9TYLf0PHfz2FmK2yVVku1a5ytOW
            yQ==
            -----END PRIVATE KEY-----
            """
        static let es512Alg: JWTAlgorithm = JWT.Algorithm.es512(privateKey: es512PrivateKey, publicKey: es512PublicKey)
        // swiftlint:disable:next line_length
        static let es512Token: String = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzUxMiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTY3OTEzMTQ0OSwiZXhwIjoxNjc5MTM1MDQ5fQ.ABMmf3dxy6Hg7sWdLQaiWIN7FZbi8Paes6FeiMcnJQPMuoT1Jnlouh7AYAH7HyaQ-G2z1h6sJ3hCyOpRjdrblP9DAaxOXUzPZhg8oLdOb6CLf6uRg32TP-TgmkusQOoAWFuj2LcxwwxfONtG3qGAibLI6cJUeAEDzgY9ua1mzLBN2Q0Z"
    }
}
