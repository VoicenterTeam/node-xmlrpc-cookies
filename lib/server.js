var http = require('http'),
    https = require('https'),
    crypto = require("crypto"),
    url = require('url'),
    EventEmitter = require('events').EventEmitter,
    Serializer = require('./serializer'),
    Deserializer = require('./deserializer'),
    { LRUCache } = require('lru-cache'),
    fs = require('fs'),
    libxmljs = require('libxmljs');  // Importing libxmljs for XML validation

// Load the XSD schema from a file
var xsdSchema = fs.readFileSync('sourefile', 'utf8');
var xsdDoc = libxmljs.parseXml(xsdSchema);  // Parse the XSD file to a document

/**
 * Function to validate XML against the XSD schema
 */
function validateXML(xml) {
  var xmlDoc = libxmljs.parseXml(xml);  // Parse the XML document
  var isValid = xmlDoc.validate(xsdDoc);  // Validate the XML against the XSD
  if(isValid){
    console.log()
  }else {
    console.error('Not valid !!!!!!!!!',xml)
  }
  return isValid;
}

/**
 * Creates a new Server object
 */
function Server(options, isSecure, onListening) {
  if (false === (this instanceof Server)) {
    return new Server(options, isSecure)
  }
  onListening = onListening || function() {}
  var that = this;

  // If a string URI is passed in, converts to URI fields
  if (typeof options === 'string') {
    options = url.parse(options);
    options.host = options.hostname;
    options.path = options.pathname;
  }
  this.loginMethodName = options.loginMethodName || "authorization.login";
  this.logoutMethodName = options.logoutMethodName || "authorization.logout";
  this.loginCookieName = options.loginCookieName || "ASP.NET_sessionID";
  this.keepAliveMethodName = options.keepAliveMethodName || "opKeepSessionAlive";

  this.lruOptions = {
    ttl: options.loginTtlMinute * 60 * 1000 || 1000 * 60 * 60,
    allowStale: false,
    updateAgeOnGet: true,
    updateAgeOnHas: true,
  };
  this.lru = new LRUCache(this.lruOptions);

  function handleMethodCall(request, response) {
    let cookies = getCookieValues(response);
    response.cookies = cookies;
    var deserializer = new Deserializer();
    deserializer.deserializeMethodCall(request, function(error, methodName, params) {
      let isLogin = false;
      if (methodName !== that.loginMethodName) {
        let sid = cookies[that.loginCookieName];
        if (sid) {
          isLogin = that.lru.get(sid);
        }
      } else {
        isLogin = true;
      }

      if (Object.prototype.hasOwnProperty.call(that._events, methodName) && isLogin) {
        that.emit(methodName, null, params, function(error, value) {
          var xml = null;
          if (error !== null) {
            xml = Serializer.serializeFault(error);
          } else {
            xml = Serializer.serializeMethodResponse(value);
          }

          // Validate the outgoing XML response
          if (!validateXML(xml)) {
            response.writeHead(500, { 'Content-Type': 'text/xml' });
            response.end('<fault><value>Invalid XML Response</value></fault>');
            return;
          }

          const headers = { 'Content-Type': 'text/xml' };
          if (methodName === that.loginMethodName && value.ErrorCode === 0) {
            let sid = crypto.randomUUID();
            if ((cookies[that.loginCookieName] || "").length > 5) {
              sid = cookies[that.loginCookieName];
            }
            that.lru.set(sid, 1);
            headers["Set-Cookie"] = `${that.loginCookieName}=${sid}`;
          } else if (methodName === that.logoutMethodName && response.cookies[that.loginCookieName]) {
            that.lru.delete(response.cookies[that.loginCookieName]);
            headers["Set-Cookie"] = `${that.loginCookieName}=0`;
          } else if (methodName === that.keepAliveMethodName) {
            that.lru.set(cookies[that.loginCookieName], 1);
          }
          validateXML(xml)
          response.writeHead(200, headers);
          response.end(xml);
        });
      } else {
        let responsMessage = 'NotFound';
        let responsCode = 404;
        if (!isLogin) {
          responsMessage = 'Not Login';
          responsCode = 401;
        }
        that.emit(responsMessage, methodName, params);
        response.writeHead(responsCode);
        response.end();
      }
    });
  }

  this.httpServer = isSecure ? https.createServer(options, handleMethodCall)
      : http.createServer(handleMethodCall);

  process.nextTick(function() {
    this.httpServer.listen(options.port, options.host, onListening);
  }.bind(this));

  this.close = function(callback) {
    this.httpServer.once('close', callback);
    this.httpServer.close();
  }.bind(this);
}

/**
 * Get cookie values from the request
 */
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

// Inherit from EventEmitter to emit and listen
Server.prototype.__proto__ = EventEmitter.prototype;

module.exports = Server;
