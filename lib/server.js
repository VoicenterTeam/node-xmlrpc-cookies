var http             = require('http')
  , https            = require('https')
    , crypto = require("crypto")
  , url              = require('url')
  , EventEmitter     = require('events').EventEmitter
  , Serializer       = require('./serializer')
  , Deserializer     = require('./deserializer')
  ,  { LRUCache } = require('lru-cache')







/**
 * Creates a new Server object. Also creates an HTTP server to start listening
 * for XML-RPC method calls. Will emit an event with the XML-RPC call's method
 * name when receiving a method call.
 *
 * @constructor
 * @param {Object|String} options - The HTTP server options. Either a URI string
 *                                  (e.g. 'http://localhost:9090') or an object
 *                                  with fields:
 *   - {String} host              - (optional)
 *   - {Number} port
 * @param {Boolean} isSecure      - True if using https for making calls,
 *                                  otherwise false.
 * @return {Server}
 */
function Server(options, isSecure, onListening) {

  if (false === (this instanceof Server)) {
    return new Server(options, isSecure)
  }
  onListening = onListening || function() {}
  var that = this

  // If a string URI is passed in, converts to URI fields
  if (typeof options === 'string') {
    options = url.parse(options)
    options.host = options.hostname
    options.path = options.pathname
  }
  this.loginMethodName = options.loginMethodName || "authorization.login"
  this.loginCookieName = options.loginCookieName || "ASP.NET_sessionID"

  this.lruOptions = {
    // how long to live in ms
    ttl: options.loginTtlMinute *60*1000 || 1000 * 60 * 60,
    // return stale items before removing from cache?
    allowStale: false,
    updateAgeOnGet: true,
    updateAgeOnHas: true,
  }
  this.lru  = new LRUCache(this.lruOptions)
  function handleMethodCall(request, response) {
    let cookies = getCookieValues(response);
    var deserializer = new Deserializer()
    deserializer.deserializeMethodCall(request, function(error, methodName, params) {
      let isLogin =false
      if (methodName !== that.loginMethodName) {
          let sid = cookies[that.loginCookieName]
          if(sid){
              isLogin = that.lru.get(sid)
          }
      }else{
          isLogin = true
      }
      if (Object.prototype.hasOwnProperty.call(that._events, methodName) && isLogin ) {
        that.emit(methodName, null, params, function(error, value) {
          var xml = null
          if (error !== null) {
            xml = Serializer.serializeFault(error)
          }
          else {
            xml = Serializer.serializeMethodResponse(value)
          }
          const  headers ={'Content-Type': 'text/xml'}
          if(methodName === that.loginMethodName && value.ErrorCode === 0) {
            let sid = crypto.randomUUID()
            that.lru.set(sid,1);
            headers["Set-Cookie"] = `${that.loginCookieName}=${sid}` ;
          }
          response.writeHead(200,headers)
          response.end(xml)
        })
      }
      else {
        let responsMessage = 'NotFound'
        let responsCode = 404
        if(!isLogin) {
          responsMessage = 'Not Login'
          responsCode = 401
        }
        that.emit(responsMessage, methodName, params)
        response.writeHead(responsCode)
        response.end()
      }
    })
  }

  this.httpServer = isSecure ? https.createServer(options, handleMethodCall)
                            : http.createServer(handleMethodCall)

  process.nextTick(function() {
    this.httpServer.listen(options.port, options.host, onListening)
  }.bind(this))
  this.close = function(callback) {
    this.httpServer.once('close', callback)
    this.httpServer.close()
  }.bind(this)
}
function getCookieValues(res){
  const data = {}
  let isVal = false
  let lastKey
  res.req.rawHeaders.forEach(value => {
    if(!isVal){
      lastKey = value
    }else{
      data[lastKey] = value
    }
    isVal=!isVal
  })
  const cookie = data.Cookie.split(';').reduce((res, item) => {     const dataCookie = item.trim().split('=');             return { ...res, [dataCookie[0]]: dataCookie[1] };         }, {});
 return cookie;


}


// Inherit from EventEmitter to emit and listen
Server.prototype.__proto__ = EventEmitter.prototype

module.exports = Server

