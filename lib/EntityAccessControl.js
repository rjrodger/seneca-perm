
var patrun = require('patrun')
var _ = require('lodash')
var AccessControlProcedure = require('access-controls')


function EntityAccessControl() {
  this._entitiesACLs = patrun()
}

EntityAccessControl.prototype.register = function(aclDef) {

  for(var j = 0 ; j < aclDef.entities.length ; j++) {
    var entity = aclDef.entities[j]

    var aclProcedure = this._entitiesACLs.find(entity)

    if(!aclProcedure) {
      aclProcedure = new AccessControlProcedure()
    }
    aclProcedure.addAccessControls(aclDef)

    this._entitiesACLs.add(entity, aclProcedure)
  }

}

EntityAccessControl.prototype._authorize = function(prior, aclAuthProcedure, entity, action, roles, context, callback) {
  aclAuthProcedure.authorize(entity, action, roles, context, function(err, result) {

    log(err, result, action, entity)

    callback(err, result)
  })
}

EntityAccessControl.prototype._authorizeRead = function(seneca, prior, args, aclAuthProcedure, action, roles, context, callback) {
  var self = this
  console.log('read check', JSON.stringify(args))
  prior(args, function(err, result) {

    if(err) {

      callback(err, undefined)

    } else if(_.isArray(result)) {

      throw new Error('SHOULD NOT GOT THERE YET')

      self._filterAccess(seneca, aclAuthProcedure, result, action, roles, context, callback)

    } else {

      console.log('entity:', result)

      self._authorize(prior, aclAuthProcedure, result, action, roles, context, callback)

    }
  })
}

EntityAccessControl.prototype._authorizeUpdate = function(seneca, prior, args, aclAuthProcedure, action, roles, context, callback) {
  var self = this
  var getArgs = _.clone(args)
  getArgs.cmd = 'load'
  getArgs.qent = getArgs.ent
  getArgs.q = {
    id: getArgs.ent.id
  }
  seneca.act(getArgs, function(err, result) {
    if(err || !result) {
      return callback(err, undefined)
    } else {
      self._authorize(aclAuthProcedure, result, action, perm.roles, context, function(err, result) {

        log(err, result, action, entityDef)

        callback(err, result)
      })
    }
  })
}


EntityAccessControl.prototype.authorizeAction = function(seneca, args, prior, callback) {

  var perm = args.perm$
  var user = args.user$

  var context = {
    user: user
  }

  var self = this

  var action = this.getAction(args)

  var entityDef = {
    zone: args.zone,
    base: args.base,
    name: args.name
  }

  //console.log('authorizing action', action, 'on entity', JSON.stringify(entityDef))

  // TODO: findall instead
  var aclAuthProcedure = this._entitiesACLs.find(entityDef)

  if(aclAuthProcedure) {

    if(action === 'r') { // for list and load action, filter/authorize after calling the 'prior' function to check obj attributes

      this._authorizeRead(seneca, prior, args, aclAuthProcedure, action, perm.roles, context, callback)
    }
    else if(action === 'u') {

      this._authorizeUpdate(seneca, prior, args, aclAuthProcedure, action, perm.roles, context, callback)

    }
    else {

      console.log(JSON.stringify(args, null, 2))

      aclAuthProcedure.authorize(args.ent, action, perm.roles, context, function(err, result) {
        log(err, result, action, entityDef)
        proceed(!err && result.authorize, 'acl', null, args, prior, callback)
      })
    }
  }
  else {
    console.log('no acl to run')
    return prior(args, callback)
  }
}

function log(err, authDecision, action, entityDetails) {
  var authorized = !err && authDecision.authorize

//   if(entityDetails.authorize) {
    console.trace()
//   }
  console.log('authorization', authorized ? 'granted' : 'denied',
              'for action [', action, ']',
              'on entity [', JSON.stringify(entityDetails), ']',
              'acls:', JSON.stringify(authDecision.history))
}


function proceed(allow,type,meta,args,parent,done) {
  if( !allow ) {
    var err = new Error('Permission denied')
    err.code = 'perm/fail/' + type
    err.status = 401
    err.args = args
    if(meta) {
      for(var attr in meta) {
        err[attr] = meta[attr]
      }
    }
    done(err)
  } else {
    parent(args, done)
  }
}

  // TODO: move this func out of this file
EntityAccessControl.prototype._filterAccess = function(seneca, aclAuthProcedure, entityList, action, roles, context, callback) {
  var filteredList = []
  var expectedCallbackCount = 0
  var stopAll = false
  // TODO: closures inside loops are evil :/ Use some recursion instead
  function createEntityAccessHandler(entity) {
    return function(err, authDecision) {

      if(stopAll) return

      if(err) {
        stopAll = true
        callback(err, undefined)
      } else {
        expectedCallbackCount --

        log(err, authDecision, action, entity)

        if(authDecision.authorize) {
          filteredList.push(entity)
        }
        if(expectedCallbackCount === 0) {
          callback(undefined, filteredList)
        }
      }
    }
  }

  if(entityList.length === 0) { // TODO: test this edge case
    return callback(undefined, filteredList)
  }
  expectedCallbackCount = entityList.length
  for(var i = 0 ; i < entityList.length ; i++) {
    aclAuthProcedure.authorize(entityList[i], action, roles, context, createEntityAccessHandler(entityList[i]))
  }
}

EntityAccessControl.prototype.getAction = function(args) {
  var action
  switch(args.cmd) {
    case "save":
      action = args.ent.id ? 'u' : 'c'
      break
    case "delete":
      action = 'd'
      break;
    case "load":
    case "list":
      action = 'r'
      break;
  }
  return action
}


module.exports = EntityAccessControl







function checkACLsWithDBEntity(seneca, entityType, entityOrId, action, roles, context, callback) {

    // TODO: findall instead
    if(_.isString(entityType)) {
      entityType = seneca.util.parsecanon(entityType)
    }

    var aclAuthProcedure = entitiesACLs.find(entityType)
    if(aclAuthProcedure) {

      if(_.isObject(entityOrId)) {
        aclAuthProcedure.authorize(entityOrId, action, roles, context, function(err, details) {

          log(err, details, action, entityType)

          callback(err, details)
        })
      } else {
        var ent = globalSeneca.make(canonize(entityType))

        ent.load$(entityOrId, function(err, entity) {
          if(err) {
            return callback(err, null)
          }
          aclAuthProcedure.authorize(entity, action, roles, context, function(err, details) {

            log(err, details, action, entityType)

            callback(err, details)
          })
        })
      }
    } else {
      setImmediate(function() {
        callback(undefined, {
          service: 'inheritance',
          authorize: true,
          control: null,
          reason: 'ACL inheritance path directs to an entity that does not have ACLs'
        })
      })

    }
  }

  // TODO: move this func out of this file
  function filterAccess(seneca, aclAuthProcedure, entityOrList, action, roles, context, callback) {
    var filteredList = []
    var expectedCallbackCount = 0
    var stopAll = false
    // TODO: closures inside loops are evil :/ Use some recursion instead
    function createEntityAccessHandler(entity) {
      return function(err, authDecision) {

        if(stopAll) return

        if(err) {
          stopAll = true
          callback(err, undefined)
        } else {

          log(err, authDecision, action, entity)

          if(authDecision.authorize && authDecision.inherit && authDecision.inherit.length > 0) {
            var inherit = authDecision.inherit[0]

            checkACLsWithDBEntity(seneca, inherit.entity, inherit.id, action, roles, context, function(err, inheritedAuthDecision) {

              expectedCallbackCount --

              if(inheritedAuthDecision && inheritedAuthDecision.authorize) {
                filteredList.push(entity)
              }
              if(expectedCallbackCount === 0) {
                callback(undefined, filteredList)
              }
            })
          } else if(authDecision.authorize) {
            expectedCallbackCount --
            filteredList.push(entity)
          } else {
            expectedCallbackCount --
          }

          if(expectedCallbackCount === 0) {
            callback(undefined, filteredList)
          }
        }
      }
    }

    if(_.isArray(entityOrList)) {
      if(entityOrList.length === 0) { // TODO: test this edge case
        return callback(undefined, filteredList)
      }
      expectedCallbackCount = entityOrList.length
      for(var i = 0 ; i < entityOrList.length ; i++) {
        aclAuthProcedure.authorize(entityOrList[i], action, roles, context, createEntityAccessHandler(entityOrList[i]))
      }
    } else {
      expectedCallbackCount = 1
      aclAuthProcedure.authorize(entityOrList, action, roles, context, function(err, authDecision) {
        if(err || !authDecision.authorize) {
          // TODO: proper 401 propagation
          callback(seneca.fail({
            action: action,
            code:'perm/fail/acl',
            entity:entityOrList,
            status:denied,
            history: authDecision.history
          }))
          //callback(err || new Error('unauthorized'), undefined)
        } else {
          if(authDecision.inherit && authDecision.inherit.length > 0) {

            var inherit = authDecision.inherit[0]
            checkACLsWithDBEntity(seneca, inherit.entity, inherit.id, action, roles, context, function(err, inheritedAuthDecision) {
              if(err || !inheritedAuthDecision.authorize) {
                // TODO: proper 401 propagation
                callback(seneca.fail({
                  action: action,
                  code:'perm/fail/acl',
                  entity:entityOrList,
                  status:denied,
                  history: authDecision.history.concat(inheritedAuthDecision.history)
                }))
              } else {
                callback(undefined, entityOrList)
              }
            })
          } else {

            callback(undefined, entityOrList)
          }
        }
      })
    }
  }
