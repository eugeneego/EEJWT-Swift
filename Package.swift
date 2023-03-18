// swift-tools-version: 5.7

import PackageDescription

let package = Package(
    name: "EEJWT",
    platforms: [
        .iOS(.v13), .tvOS(.v13), .watchOS(.v6), .macOS(.v10_15),
    ],
    products: [
        .library(name: "EEJWT", targets: ["EEJWT"]),
    ],
    dependencies: [],
    targets: [
        .target(name: "EEJWT", dependencies: []),
        .testTarget(name: "EEJWTTests", dependencies: ["EEJWT"]),
    ]
)
