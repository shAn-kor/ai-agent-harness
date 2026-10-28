// Touch ID-backed signer for review-gate close receipts.
//
//   approver init   --key <file> --pub <file>
//   approver sign   --key <file> --message <file|-> --reason <text>
//   approver verify --pub <file> --message <file|-> --signature <base64>
//   approver public --key <file>
//
// `public` prints the PEM public key of a key file, exactly as `init` wrote
// it to --pub. It needs no user presence, so the installer can check which
// key file matches the pinned key.
//
// `--message -` reads the message from standard input, so no other process
// running as the user can swap a message file between write and read.
//
// The private key lives in the Secure Enclave. The key file holds only an
// encrypted handle that this Mac's Secure Enclave can use, and every signature
// requires user presence (Touch ID or the login password).

import CryptoKit
import Foundation
import LocalAuthentication

func fail(_ message: String, _ code: Int32 = 2) -> Never {
    FileHandle.standardError.write(Data("approver: \(message)\n".utf8))
    exit(code)
}

func option(_ name: String) -> String {
    let args = CommandLine.arguments
    guard let i = args.firstIndex(of: name), i + 1 < args.count else {
        fail("missing \(name)")
    }
    return args[i + 1]
}

func read(_ path: String) -> Data {
    if path == "-" {
        return FileHandle.standardInput.readDataToEndOfFile()
    }
    guard let data = FileManager.default.contents(atPath: path) else {
        fail("cannot read \(path)")
    }
    return data
}

guard CommandLine.arguments.count > 1 else {
    fail("usage: approver init|sign|verify ...")
}

switch CommandLine.arguments[1] {
case "init":
    guard SecureEnclave.isAvailable else { fail("no Secure Enclave") }
    let keyPath = option("--key")
    if FileManager.default.fileExists(atPath: keyPath) {
        fail("\(keyPath) exists; refusing to replace a key")
    }
    var error: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.privateKeyUsage, .userPresence], &error
    ) else { fail("access control: \(String(describing: error))") }
    do {
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        let created = FileManager.default.createFile(
            atPath: keyPath, contents: key.dataRepresentation,
            attributes: [.posixPermissions: 0o600]
        )
        guard created else { fail("cannot write \(keyPath)") }
        try key.publicKey.pemRepresentation.write(
            toFile: option("--pub"), atomically: true, encoding: .utf8
        )
    } catch {
        fail("key creation failed: \(error)")
    }
case "sign":
    let context = LAContext()
    context.localizedReason = option("--reason")
    do {
        let key = try SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: read(option("--key")), authenticationContext: context
        )
        let signature = try key.signature(for: read(option("--message")))
        print(signature.derRepresentation.base64EncodedString())
    } catch {
        fail("signing failed or was cancelled: \(error)", 1)
    }
case "public":
    do {
        let key = try SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: read(option("--key"))
        )
        FileHandle.standardOutput.write(Data(key.publicKey.pemRepresentation.utf8))
    } catch {
        fail("not a key for this Secure Enclave: \(error)", 1)
    }
case "verify":
    do {
        let pem = String(decoding: read(option("--pub")), as: UTF8.self)
        let key = try P256.Signing.PublicKey(pemRepresentation: pem)
        guard let der = Data(base64Encoded: option("--signature")) else {
            fail("signature is not base64", 1)
        }
        let signature = try P256.Signing.ECDSASignature(derRepresentation: der)
        exit(key.isValidSignature(signature, for: read(option("--message"))) ? 0 : 1)
    } catch {
        fail("verification error: \(error)", 1)
    }
default:
    fail("unknown command \(CommandLine.arguments[1])")
}
