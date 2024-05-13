//
//  JWTTokenValidator.swift
//  JWTTokenValidator
//
//  Created by Thomas (privat) Leonhardt on 10.05.24.
//

import Foundation
import SwiftUI
import JWTKit

public class JWTTokenValidator {
    private var keyCollection = JWTKeyCollection()
    let key: String
    
    public required init(key: String) {
        self.key = key
    }
    
    public func verify<T: JWTPayload>(_ token: String, digestAlgorithm: DigestAlgorithm, type: T.Type) async throws -> T? {
            let keys = await keyCollection.addHMAC(key: key, digestAlgorithm: digestAlgorithm)
            return try await keys.verify(token, as: T.self)
    }
    
    public func createToken(payload: JWTPayload, digestAlgorithm: DigestAlgorithm) async throws -> String {
        let keys = await keyCollection.addHMAC(key: key, digestAlgorithm: digestAlgorithm)
        return try await keys.sign(payload, header: [:])
    }
}
