//
//  WebHookManager.swift
//  Jared
//
//  Created by Zeke Snider on 2/2/19.
//  Copyright © 2019 Zeke Snider. All rights reserved.
//

import Foundation
import JaredFramework
import CryptoKit

class WebHookManager: MessageDelegate, RoutingModule {
    var urlSession: URLSession
    var webhooks = [Webhook]()
    var routes = [Route]()
    var sender: MessageSender
    var description = "Routes provided by webhooks"
    
    public init(webhooks: [Webhook]?, session: URLSessionConfiguration = URLSessionConfiguration.ephemeral, sender: MessageSender) {
        session.timeoutIntervalForResource = 10.0
        self.sender = sender
        urlSession = URLSession(configuration: session)
        
        updateHooks(to: webhooks)
    }
    
    required convenience init(sender: MessageSender) {
        self.init(webhooks: nil, session: URLSessionConfiguration.ephemeral, sender: sender)
    }
    
    public func didProcess(message: Message) {
        // loop over all webhooks, if the list is null, do nothing.
        for webhook in webhooks {
            // if a webhook has routes, we shouldn't call it for every message
            guard (webhook.routes?.isEmpty ?? true) else {
                continue
            }
            
            notifyRoute(message, url: webhook.url, secret: webhook.secret)
        }
    }
    
    public func notifyRoute(_ message: Message, url: String, secret: String? = nil) {
        NSLog("Notifying \(url) of new message event")
        
        guard let parsedUrl = URL(string: url) else {
            NSLog("Unable to parse URL for webhook \(url)")
            return
        }
        guard let webhookBody = WebHookManager.createWebhookBody(message) else {
            NSLog("Unable to encode webhook body for \(url)")
            return
        }
        
        var request = URLRequest(url: parsedUrl)
        request.httpMethod = "POST"
        request.httpBody = webhookBody
        request.setValue("application/json; charset=utf-8", forHTTPHeaderField: "Content-Type")
        
        // Add HMAC signature headers if secret is configured (treat empty string as no secret)
        if let secret = secret, !secret.isEmpty {
            addSignatureHeaders(to: &request, body: webhookBody, secret: secret)
        }
        
        urlSession.dataTask(with: request) { data, response, error in
            guard error == nil, let data = data, let httpResponse = response as? HTTPURLResponse,
                (200...299).contains(httpResponse.statusCode) else {
                NSLog("Received error while requesting webhook \(error.debugDescription)")
                return
            }
            guard let decoded = try? JSONDecoder().decode(WebhookResponse.self, from: data) else {
                NSLog("Unable to parse response from webhook")
                return
            }
            
            if (decoded.success) {
                if let decodedBody = decoded.body?.message {
                    self.sender.send(decodedBody, to: message.RespondTo())
                }
            } else {
                if let decodedError = decoded.error {
                    NSLog("Got back error from webhook. \(decodedError)")
                    return
                }
            }
        }.resume()
    }
    
    /// Adds HMAC-SHA256 signature headers to the request for verification by the receiving server.
    /// Headers added:
    /// - X-Timestamp: Unix timestamp (seconds since epoch)
    /// - X-Nonce: Unique UUID to prevent replay attacks
    /// - X-Signature: HMAC-SHA256(secret, timestamp + \0 + nonce + \0 + body) as hex string
    ///
    /// The payload uses NUL (\0) delimiters to prevent ambiguous concatenation attacks.
    private func addSignatureHeaders(to request: inout URLRequest, body: Data, secret: String) {
        let timestamp = String(Int(Date().timeIntervalSince1970))
        let nonce = UUID().uuidString
        
        // Build payload with NUL delimiters: timestamp + \0 + nonce + \0 + body
        // Using raw bytes avoids UTF-8 conversion issues and is more robust
        var payload = Data()
        payload.append(contentsOf: timestamp.utf8)
        payload.append(0) // NUL delimiter
        payload.append(contentsOf: nonce.utf8)
        payload.append(0) // NUL delimiter
        payload.append(body)
        
        let secretKey = SymmetricKey(data: Data(secret.utf8))
        let mac = HMAC<SHA256>.authenticationCode(for: payload, using: secretKey)
        let signatureHex = mac.map { String(format: "%02x", $0) }.joined()
        
        // Use setValue (not addValue) to avoid duplicate headers
        request.setValue(timestamp, forHTTPHeaderField: "X-Timestamp")
        request.setValue(nonce, forHTTPHeaderField: "X-Nonce")
        request.setValue(signatureHex, forHTTPHeaderField: "X-Signature")
    }
    
    public func updateHooks(to hooks: [Webhook]?) {
        // Change all routes to have a callback that calls the webhook manager's
        // notify route method
        self.webhooks = (hooks ?? []).map({ (hook) -> Webhook in
            var newHook = hook
            newHook.routes = (newHook.routes ?? []).map({ (route) -> Route in
                var newRoute = route
                newRoute.call = {[weak self] in
                    self?.notifyRoute($0, url: newHook.url, secret: newHook.secret)
                }
                return newRoute
            })
            
            return newHook
        })
        
        self.routes = self.webhooks.flatMap({ $0.routes ?? [] })
        NSLog("Webhooks updated to: \(self.webhooks.map{ $0.url }.joined(separator: ", "))")
    }

    static private func createWebhookBody(_ message: Message) -> Data? {
        return try? JSONEncoder().encode(message)
    }
}
