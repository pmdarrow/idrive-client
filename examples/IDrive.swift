import Foundation
import IdriveCore

/// Swift adapter. Initialize on a background task; C calls block.
public final class IDriveSession: @unchecked Sendable {
    private let handle: OpaquePointer
    private let queue = DispatchQueue(label: "idrive.native", attributes: .concurrent)
    public enum Failure: Error { case authentication, invalidResponse, service(String) }

    public init(username: String, password: String) throws {
        let json = try JSONSerialization.data(withJSONObject: ["username": username, "password": password])
        guard let text = String(data: json, encoding: .utf8),
              let handle = text.withCString({ idrive_client_open($0) }) else { throw Failure.authentication }
        self.handle = handle
    }
    deinit { idrive_client_close(handle) }

    public func call(_ request: [String: String]) async throws -> Data {
        let json = try JSONSerialization.data(withJSONObject: request)
        guard let text = String(data: json, encoding: .utf8) else { throw Failure.invalidResponse }
        return try await withCheckedThrowingContinuation { continuation in
            queue.async { [self] in
                do {
                    let result = text.withCString { idrive_client_call(handle, $0) }
                    guard let result else { throw Failure.invalidResponse }
                    defer { idrive_string_free(result) }
                    let data = Data(String(cString: result).utf8)
                    let value = try JSONSerialization.jsonObject(with: data) as? [String: Any]
                    guard value?["ok"] as? Bool == true else {
                        throw Failure.service(value?["error"] as? String ?? "Unknown service error")
                    }
                    continuation.resume(returning: data)
                } catch { continuation.resume(throwing: error) }
            }
        }
    }
}
