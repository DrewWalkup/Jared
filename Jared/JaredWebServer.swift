import Foundation
import Telegraph
import JaredFramework
import CryptoKit

class JaredWebServer: NSObject {
    static var DEFAULT_PORT = 3000
    var defaults: UserDefaults!
    var server: Server!
    var port: Int!
    var secret: String?
    var sender: MessageSender
    
    // Nonce cache for replay protection (nonce -> expiry timestamp)
    private var seenNonces: [String: Int] = [:]
    private let nonceLock = NSLock()
    
    init(sender: MessageSender, configuration: WebserverConfiguration) {
        self.sender = sender
        self.secret = configuration.secret
        super.init()
        defaults = UserDefaults.standard
        server = Server()
        server.route(.POST, "message", handleMessageRequest)
        
        port = configuration.port
        
        defaults.addObserver(self, forKeyPath: JaredConstants.restApiIsDisabled, options: .new, context: nil)
        updateServerState()
    }
    
    deinit {
        stop()
        UserDefaults.standard.removeObserver(self, forKeyPath: JaredConstants.restApiIsDisabled)
    }
    
    override func observeValue(forKeyPath keyPath: String?, of object: Any?, change: [NSKeyValueChangeKey : Any]?, context: UnsafeMutableRawPointer?) {
        if (keyPath == JaredConstants.restApiIsDisabled) {
            updateServerState()
        }
    }
    
    func updateServerState() {
        if (defaults.bool(forKey: JaredConstants.restApiIsDisabled)) {
            stop()
        } else {
            start()
        }
        
    }
    
    public func start() {
        try? server.start(port: port)
    }
    
    public func stop() {
        server.stop()
    }
    
    private func handleMessageRequest(request: HTTPRequest) -> HTTPResponse {
        // Verify HMAC signature if secret is configured
        if let secret = secret, !secret.isEmpty {
            guard verifySignature(request: request, secret: secret) else {
                return HTTPResponse(HTTPStatus(code: 401, phrase: "Unauthorized"), headers: HTTPHeaders(), content: "Invalid or missing signature")
            }
        }
        
        // Attempt to decode the request body to the MessageRequest struct
        do {
            let parsedBody = try JSONDecoder().decode(MessageRequest.self, from: request.body)
            
            let textBody = parsedBody.body as? TextBody
            
            guard (textBody != nil || parsedBody.attachments != nil) else {
                return HTTPResponse(HTTPStatus(code: 400, phrase: "Bad Request"), headers: HTTPHeaders(), content: "A text body and/or attachments are required")
            }
            
            let message = Message(body: parsedBody.body, date: Date(), sender: Person(givenName: nil, handle: "", isMe: true), recipient: parsedBody.recipient, attachments: parsedBody.attachments ?? [], sendStyle: nil, associatedMessageType: nil, associatedMessageGUID: nil)
            
            sender.send(message)
            return HTTPResponse()
        } catch {
            return HTTPResponse(HTTPStatus(code: 400, phrase: "Bad Request"), headers: HTTPHeaders(), content: error.localizedDescription)
        }
    }
    
    /// Gets a header value case-insensitively
    private func getHeader(_ request: HTTPRequest, name: String) -> String? {
        // Try exact match first
        if let value = request.headers[name] {
            return value
        }
        // Try case-insensitive lookup
        let lowercaseName = name.lowercased()
        for (key, value) in request.headers {
            // HTTPHeaderName conforms to CustomStringConvertible
            if String(describing: key).lowercased() == lowercaseName {
                return value
            }
        }
        return nil
    }
    
    /// Checks if a nonce has been seen (for replay protection)
    /// Returns true if nonce is fresh, false if replayed
    private var pruneCounter = 0
    private let maxNonceCount = 50_000  // Safety cap to prevent memory exhaustion
    private func checkAndStoreNonce(_ nonce: String, expiresAt: Int) -> Bool {
        nonceLock.lock()
        defer { nonceLock.unlock() }
        
        let now = Int(Date().timeIntervalSince1970)
        
        // Prune expired nonces every 200 checks, or immediately if over max
        pruneCounter += 1
        if pruneCounter >= 200 || seenNonces.count > maxNonceCount {
            pruneCounter = 0
            seenNonces = seenNonces.filter { $0.value > now }
            if seenNonces.count > maxNonceCount {
                NSLog("Nonce cache overflow, clearing")
                seenNonces.removeAll()
            }
        }
        
        // Check if nonce exists and is not expired
        if let existingExpiry = seenNonces[nonce], existingExpiry > now {
            return false // Replay detected
        }
        
        // Store the nonce
        seenNonces[nonce] = expiresAt
        return true
    }
    
    /// Verifies HMAC-SHA256 signature on incoming requests.
    /// Expected headers: X-Timestamp, X-Nonce, X-Signature
    /// Signature payload: timestamp + \0 + nonce + \0 + body (raw bytes with NUL delimiters)
    private func verifySignature(request: HTTPRequest, secret: String, maxAgeSeconds: Int = 60) -> Bool {
        // Get headers case-insensitively
        guard let timestamp = getHeader(request, name: "X-Timestamp"),
              let nonce = getHeader(request, name: "X-Nonce"),
              let signatureHeader = getHeader(request, name: "X-Signature") else {
            NSLog("Missing HMAC signature headers")
            return false
        }
        
        // Normalize all header values (trim whitespace)
        let ts = timestamp.trimmingCharacters(in: .whitespacesAndNewlines)
        let nn = nonce.trimmingCharacters(in: .whitespacesAndNewlines)
        let signature = signatureHeader.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        
        // Validate signature format: must be exactly 64 ASCII hex characters [0-9a-f]
        guard signature.count == 64,
              signature.unicodeScalars.allSatisfy({ ($0.value >= 48 && $0.value <= 57) || ($0.value >= 97 && $0.value <= 102) }) else {
            NSLog("Invalid signature format")
            return false
        }
        
        // Check timestamp freshness
        guard let requestTime = Int(ts) else {
            NSLog("Invalid timestamp format")
            return false
        }
        
        let now = Int(Date().timeIntervalSince1970)
        if requestTime > now + maxAgeSeconds {
            NSLog("Request timestamp too far in the future")
            return false
        }
        if now - requestTime > maxAgeSeconds {
            NSLog("Request timestamp too old")
            return false
        }
        
        // Build expected signature payload with NUL delimiters (use trimmed values)
        var payload = Data()
        payload.append(contentsOf: ts.utf8)
        payload.append(0) // NUL delimiter
        payload.append(contentsOf: nn.utf8)
        payload.append(0) // NUL delimiter
        payload.append(request.body)
        
        // Compute expected MAC
        let secretKey = SymmetricKey(data: Data(secret.utf8))
        let mac = HMAC<SHA256>.authenticationCode(for: payload, using: secretKey)
        let expectedSignature = mac.map { String(format: "%02x", $0) }.joined()
        
        // Constant-time comparison (both are 64 chars due to earlier validation)
        var result: UInt8 = 0
        for (a, b) in zip(signature.utf8, expectedSignature.utf8) {
            result |= a ^ b
        }
        
        guard result == 0 else {
            NSLog("Signature verification failed")
            return false
        }
        
        // Replay protection AFTER signature verification (prevents DoS via nonce flooding)
        let expiresAt = requestTime + maxAgeSeconds  // Use request timestamp, not server time
        guard checkAndStoreNonce(nn, expiresAt: expiresAt) else {
            NSLog("Nonce replay detected")
            return false
        }
        
        return true
    }
}
