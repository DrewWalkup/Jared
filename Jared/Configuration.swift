//
//  Configuration.swift
//  Jared
//
//  Created by Zeke Snider on 8/17/20.
//  Copyright © 2020 Zeke Snider. All rights reserved.
//

import Foundation

struct ConfigurationFile: Decodable {
    let routes: [String: RouteConfiguration]
    let webhooks: [Webhook]
    let webServer: WebserverConfiguration
    
    init() {
        routes = [:]
        webhooks = []
        webServer = WebserverConfiguration(port: 3000)
    }
}

struct WebserverConfiguration: Decodable {
    let port: Int
    let secret: String?  // HMAC shared secret for request verification
    
    init(port: Int, secret: String? = nil) {
        self.port = port
        self.secret = secret
    }
}

struct RouteConfiguration: Decodable {
    let disabled: Bool
}
