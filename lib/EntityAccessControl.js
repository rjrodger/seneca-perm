
var patrun = require('patrun')
var AccessControlProcedure = require('./AccessControlProcedure.js')


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

    this._entitiesACLs.add(acl.entities[j], aclProcedure)
  }

}

EntityAccessControl.prototype._authorize = function(prior, aclAuthProcedure, entity, action, roles, context, callback) {
  aclAuthProcedure.authorize(entity, action, roles, context, function(err, result) {
    var authorized = !err && result.authorize
    seneca.log.debug('authorization', authorized ? 'granted' : 'denied',
                    'for action [', action, ']',
                    'on entity [', entityDef.zone + '/' + entityDef.base + '/'+entityDef.name, ']',
                     'acls:', result.history)
    callback(err, result)
  })
}

EntityAccessControl.prototype._authorizeRead = function(seneca, prior, entity, action, roles, context, callback) {
  prior(args, function(err, result) {
    if(err) {
      done(err, undefined)
    }
    else if(_.isArray(result)) {
      self._filterAccess(seneca, aclAuthProcedure, result, action, perm.roles, context, done)
    } else {
    }
  })
}

EntityAccessControl.prototype._authorizeUpdate = function(aclAuthProcedure, entity, action, roles, context, callback) {
  var self = this
  var getArgs = _.clone(args)
  getArgs.cmd = 'load'
  getArgs.qent = getArgs.ent
  getArgs.q = {
    id: getArgs.ent.id
  }
  seneca.act(getArgs, function(err, result) {
    if(err || !result) {
      return done(err, undefined)
    } else {
      self._authorize(aclAuthProcedure, result, action, perm.roles, context, function(err, result) {
        var authorized = !err && result.authorize
        seneca.log.info('authorization', authorized ? 'granted' : 'denied',
                        'for action [', action, ']',
                        'on entity [', entityDef.zone + '/' + entityDef.base + '/'+entityDef.name, ']',
                         'acls:', result.history)
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

  // TODO: findall instead
  var aclAuthProcedure = this._entitiesACLs.find(entityDef)

  if(aclAuthProcedure) {

    if(action === 'r') { // for list and load action, filter/authorize after calling the 'prior' function to check obj attributes

      this._authorizeRead(prior, args.ent, action, perm.roles, context, callback)
    }
    else if(action === 'u') {

      this._authorizeUpdate(prior, args.ent, action, perm.roles, context, callback)

    }
    else {

      aclAuthProcedure.authorize(args.ent, action, perm.roles, context, function(err, result) {
        var authorized = !err && result.authorize
        seneca.log.info('authorization', authorized ? 'granted' : 'denied',
                        'for action [', action, ']',
                        'on entity [', entityDef.zone + '/' + entityDef.base + '/'+entityDef.name, ']',
                         'acls:', result.history)
        proceed(!err && result.authorize, 'acl', null, args, prior, done)
      })
    }
  }
  else {
    return prior(args, done)
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

        seneca.log.info('authorization', authDecision.authorize ? 'granted' : 'denied',
                        'for action [', action, ']',
                        'on entity [',  entity.id, ']',
                         'acls:', authDecision.history)

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
