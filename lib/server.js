var http = require('http'),
    https = require('https'),
    crypto = require("crypto"),
    url = require('url'),
    EventEmitter = require('events').EventEmitter,
    Serializer = require('./serializer'),
    Deserializer = require('./deserializer'),
    { LRUCache } = require('lru-cache'),
    fs = require('fs'),
    libxmljs = require('libxmljs');

// Load the XSD schema from a file
var xsdSchema = fs.readFileSync('Venus_XSD.xsd', 'utf8');
var xsdDoc = libxmljs.parseXml(xsdSchema);

// Enhanced Session Manager
class SessionManager {
  constructor(ttlMinutes) {
    this.ttlMilliseconds = ttlMinutes * 60 * 1000;
    this.sessions = new LRUCache({
      max: 1000,
      ttl: this.ttlMilliseconds,
      allowStale: false,
      updateAgeOnGet: true,
      updateAgeOnHas: true,
    });

    this.startSessionMonitoring();
  }
  // New method to log session details
  logSessionDetails() {
    const currentTime = Date.now();
    const activeSessionDetails = [];
    const expiredSessionDetails = [];

    // Iterate through all sessions
    this.sessions.forEach((sessionData, sessionId) => {
      // Ensure sessionId is not null or undefined
      if (!sessionId) {
        console.warn('[SESSION MONITOR] Encountered session with null/undefined sessionId');
        return;
      }

      const sessionInfo = {
        sessionId,
        createdAt: new Date(sessionData.createdAt).toISOString(),
        expiresAt: new Date(sessionData.expiresAt).toISOString(),
        timeRemaining: Math.max(0, sessionData.expiresAt - currentTime) / 1000 + ' seconds',
        status: sessionData.expiresAt > currentTime ? 'ACTIVE' : 'EXPIRED',
        loginCount: sessionData.loginCount || 1,
        sourceIPs: sessionData.sourceHistory ?
            sessionData.sourceHistory.map(source => source.ipAddress).join(', ') : 'N/A',
        lastSourceHostname: sessionData.sourceHistory && sessionData.sourceHistory[0]
            ? sessionData.sourceHistory[0].hostname : 'N/A'
      };

      if (sessionData.expiresAt > currentTime) {
        activeSessionDetails.push(sessionInfo);
      } else {
        expiredSessionDetails.push(sessionInfo);
      }
    });

    // Comprehensive Session Report
    console.log('==================================================');
    console.log(`[SESSION MONITOR] - ${new Date().toISOString()}`);
    console.log('==================================================');

    console.log('Active Sessions:');
    console.table(activeSessionDetails);

    console.log('\nExpired Sessions:');
    console.table(expiredSessionDetails);

    console.log('==================================================');
    console.log(`Total Active Sessions: ${activeSessionDetails.length}`);
    console.log(`Total Expired Sessions: ${expiredSessionDetails.length}`);
    console.log('==================================================');
  }

  startSessionMonitoring() {
    // Log sessions every minute
    this.sessionMonitorInterval = setInterval(() => {
      try {
        this.logSessionDetails();
      } catch (error) {
        console.error('[SESSION MONITOR] Error:', error);
      }
    }, 60 * 1000); // 1 minute interval
  }

  createSession(loginResponse, existingSessionId = null, requestDetails = {}) {
    const currentTime = Date.now();

    // Always generate a new session ID if not provided or invalid
    let sessionId = existingSessionId || crypto.randomUUID();

    // Prepare detailed request source information
    const sourceDetails = {
      timestamp: new Date().toISOString(),
      ipAddress: requestDetails.ipAddress || 'Unknown',
      userAgent: requestDetails.userAgent || 'Unknown',
      protocol: requestDetails.protocol || 'Unknown',
      hostname: requestDetails.hostname || 'Unknown',
      method: requestDetails.method || 'Unknown',
      requestHeaders: requestDetails.headers ?
          Object.keys(requestDetails.headers).reduce((acc, key) => {
            // Filter sensitive headers, truncate long values
            if (!key.toLowerCase().includes('password') &&
                !key.toLowerCase().includes('authorization')) {
              acc[key] = (requestDetails.headers[key] + '').substring(0, 100);
            }
            return acc;
          }, {}) : {}
    };

    // Check if existing session is valid
    let sessionData = this.sessions.get(sessionId);

    // If no valid session exists, create new session data
    if (!sessionData || sessionData.expiresAt <= currentTime) {
      // Generate a new session ID if the existing one is invalid
      sessionId = crypto.randomUUID();

      sessionData = {
        userData: {
          loginResponse,
          sourceDetails
        },
        createdAt: currentTime,
        expiresAt: currentTime + this.ttlMilliseconds,
        loginCount: 1,
        sourceHistory: [sourceDetails]
      };

      console.log(`[SESSION] New Session Created: ${sessionId}`, {
        createdAt: new Date(sessionData.createdAt).toISOString(),
        expiresAt: new Date(sessionData.expiresAt).toISOString(),
        timeToLive: this.ttlMilliseconds / 1000 + ' seconds',
        sourceIP: sourceDetails.ipAddress,
        hostname: sourceDetails.hostname
      });
    } else {
      // Existing session: update login information
      sessionData.loginCount++;

      // Add to source history (keep last 5 entries)
      if (!sessionData.sourceHistory) {
        sessionData.sourceHistory = [];
      }
      sessionData.sourceHistory.unshift(sourceDetails);
      sessionData.sourceHistory = sessionData.sourceHistory.slice(0, 5);

      // Extend TTL if conditions are met
      const timeRemaining = sessionData.expiresAt - currentTime;
      const shouldExtendTTL = timeRemaining < (this.ttlMilliseconds * 0.25);

      if (shouldExtendTTL) {
        sessionData.expiresAt = currentTime + this.ttlMilliseconds;

        console.log(`[SESSION] Session TTL Extended: ${sessionId}`, {
          originalCreatedAt: new Date(sessionData.createdAt).toISOString(),
          newExpiresAt: new Date(sessionData.expiresAt).toISOString(),
          loginCount: sessionData.loginCount,
          timeToLive: this.ttlMilliseconds / 1000 + ' seconds',
          sourceIP: sourceDetails.ipAddress
        });
      }
    }

    // Always update the session with the latest data
    this.sessions.set(sessionId, sessionData);

    return sessionId;
  }


  validateSession(sessionId) {
    if (!this.sessions.has(sessionId)) {
      console.log(`[SESSION] Validation Failed: Session not found - ${sessionId}`);
      return null;
    }

    const sessionData = this.sessions.get(sessionId);
    const currentTime = Date.now();
    const timeRemaining = sessionData.expiresAt - currentTime;

    if (timeRemaining <= 0) {
      console.log(`[SESSION] Expired: ${sessionId}`, {
        createdAt: new Date(sessionData.createdAt).toISOString(),
        expiresAt: new Date(sessionData.expiresAt).toISOString(),
        currentTime: new Date(currentTime).toISOString()
      });
      this.sessions.delete(sessionId);
      return null;
    }

    console.log(`[SESSION] Validated: ${sessionId}`, {
      timeRemaining: timeRemaining / 1000 + ' seconds',
      expiresAt: new Date(sessionData.expiresAt).toISOString()
    });

    return sessionData.userData;
  }

  removeSession(sessionId) {
    console.log(`[SESSION] Removed: ${sessionId}`);
    this.sessions.delete(sessionId);
  }

  extendSessionTTL(sessionId) {
    if (!this.sessions.has(sessionId)) {
      console.log(`[SESSION] TTL Extension Failed: Session not found - ${sessionId}`);
      return false;
    }

    const sessionData = this.sessions.get(sessionId);
    sessionData.expiresAt = Date.now() + this.ttlMilliseconds;

    this.sessions.set(sessionId, sessionData);

    console.log(`[SESSION] TTL Extended: ${sessionId}`, {
      newExpiresAt: new Date(sessionData.expiresAt).toISOString(),
      timeToLive: this.ttlMilliseconds / 1000 + ' seconds'
    });

    return true;
  }

  getSessionDetails(sessionId) {
    if (!this.sessions.has(sessionId)) {
      return null;
    }

    const sessionData = this.sessions.get(sessionId);
    const currentTime = Date.now();

    return {
      sessionId,
      createdAt: new Date(sessionData.createdAt).toISOString(),
      expiresAt: new Date(sessionData.expiresAt).toISOString(),
      timeRemaining: (sessionData.expiresAt - currentTime) / 1000 + ' seconds',
      isValid: sessionData.expiresAt > currentTime
    };
  }
}

function validateXML(xml) {
    try {
        var xmlDoc = libxmljs.parseXml(xml);
        var isValid = xmlDoc.validate(xsdDoc);
        if (!isValid) {
            console.error('XML Validation Failed:', xml);
        }
        return isValid;
    } catch (error) {
        console.error('XML Parsing Error:', error);
        return false; 
    }
}

function Server(options, isSecure, onListening) {
  if (false === (this instanceof Server)) {
    return new Server(options, isSecure);
  }

  const that = this;
  onListening = onListening || function() {};

  if (typeof options === 'string') {
    options = url.parse(options);
    options.host = options.hostname;
    options.path = options.pathname;
  }

  // Configuration
  this.loginIsNoRequire = options.loginIsNoRequire || [
    'GetDidInfo',
    'GetCustomerInfo',
    'CustomerProvision',
    'DeleteDid',
    'DeleteCustomer',
    'DIDProvision'
  ];
  this.loginMethodName = options.loginMethodName || "authorization.login";
  this.logoutMethodName = options.logoutMethodName || "authorization.logout";
  this.loginCookieName = options.loginCookieName || "ASP.NET_sessionID";
  this.keepAliveMethodName = options.keepAliveMethodName || "opKeepSessionAlive";

  // Initialize session manager
  this.sessionManager = new SessionManager(options.loginTtlMinute || 60);

  function handleMethodCall(request, response) {
    // Prepare request details
    const requestDetails = {
      ipAddress: request.socket.remoteAddress,
      userAgent: request.headers['user-agent'],
      protocol: request.protocol,
      hostname: request.hostname,
      method: request.method,
      headers: request.headers
    };

    var deserializer = new Deserializer();
    deserializer.deserializeMethodCall(request, function(error, methodName, params) {
      if (error) {
        response.writeHead(400, { 'Content-Type': 'text/xml' });
        response.end(Serializer.serializeFault(error));
        return;
      }

      // Authentication check
      const isPublicMethod = that.loginIsNoRequire.includes(methodName);
      const isLoginAttempt = methodName === that.loginMethodName;
      const isDeveloperMode = process.env.DEVELOPER_MODE
      let isAuthenticated = false;

      // Existing session management logic
      const cookies = getCookieValues(response);
      const sessionId = cookies[that.loginCookieName];

      if (isPublicMethod || isLoginAttempt || isDeveloperMode ) {
        isAuthenticated = true;
      } else {
        const sessionData = that.sessionManager.validateSession(sessionId);
        isAuthenticated = !!sessionData;
      }

      if (!isAuthenticated && !isLoginAttempt) {
        response.writeHead(401, { 'Content-Type': 'text/xml' });
        response.end(Serializer.serializeFault({ code: 401, message: 'Unauthorized' }));
        return;
      }

      // Handle method execution
      if (Object.prototype.hasOwnProperty.call(that._events, methodName)) {
        that.emit(methodName, null, params, function(error, value) {
          if (error) {
            response.writeHead(500, { 'Content-Type': 'text/xml' });
            response.end(Serializer.serializeFault(error));
            return;
          }

          const xml = Serializer.serializeMethodResponse(value);
          if (!validateXML(xml)) {
              response.writeHead(500, { 'Content-Type': 'text/xml' });
              response.end(Serializer.serializeFault({ code: 500, message: 'Invalid XML Response' }));
              return;
          }

          const headers = { 'Content-Type': 'text/xml' };

          // Session management
          if (isLoginAttempt && value.ErrorCode === 0) {
            // Pass request details and login response to session creation
            const newSessionId = that.sessionManager.createSession(
                value,  // login response
                sessionId,  // existing session ID
                requestDetails  // request details
            );
            headers['Set-Cookie'] = `${that.loginCookieName}=${newSessionId}; HttpOnly; Path=/`;
          } else if (methodName === that.logoutMethodName) {
            that.sessionManager.removeSession(sessionId);
            headers['Set-Cookie'] = `${that.loginCookieName}=; HttpOnly; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT`;
          } else if (methodName === that.keepAliveMethodName) {
            const refreshResult = that.sessionManager.extendSessionTTL(sessionId);
            if (!refreshResult) {
              response.writeHead(401, { 'Content-Type': 'text/xml' });
              response.end(Serializer.serializeFault({ code: 401, message: 'Session Refresh Failed' }));
              return;
            }
          }

          response.writeHead(200, headers);
          response.end(xml);
        });
      } else {
        response.writeHead(404, { 'Content-Type': 'text/xml' });
        response.end(Serializer.serializeFault({ code: 404, message: 'Method Not Found' }));
      }
    });
  }

  this.httpServer = isSecure
      ? https.createServer(options, handleMethodCall)
      : http.createServer(handleMethodCall);

  process.nextTick(function() {
    this.httpServer.listen(options.port, options.host, onListening);
  }.bind(this));

  this.close = function(callback) {
    this.httpServer.once('close', callback);
    this.httpServer.close();
  }.bind(this);
}

function getCookieValues(res) {
  const data = {};
  let isVal = false;
  let lastKey;
  res.req.rawHeaders.forEach(value => {
    if (!isVal) {
      lastKey = value;
    } else {
      data[lastKey] = value;
    }
    isVal = !isVal;
  });

  let cookie = {};
  if (data.Cookie && data.Cookie.length > 0) {
    cookie = data.Cookie.split(';').reduce((res, item) => {
      const dataCookie = item.trim().split('=');
      return { ...res, [dataCookie[0]]: dataCookie[1] };
    }, {});
  }
  return cookie;
}

Server.prototype.__proto__ = EventEmitter.prototype;

module.exports = Server;
