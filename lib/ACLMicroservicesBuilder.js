
var patrun = require('patrun')
var _ = require('lodash')
var AccessControlProcedure = require('access-controls')

var DEBUG=true

var ACL_ERROR_CODE = 'perm/fail/acl'

function debug() {
  if(DEBUG) {
    console.log.apply(console, arguments)
  }
}

function ACLMicroservicesBuilder(seneca) {
  this._ACLProcedureResolver = patrun()
  this._seneca = seneca

  var self = this

//   seneca.add({role: 'entity', cmd: 'save'}, function(args, callback) {
//     console.log(JSON.stringify(args))
//     this.prior(args, callback)
//   })

  this._executeReadPermissionsWrapper = function(args, callback) {

    if(args.perm$) {

      self._executeReadPermissions(args, callback)

    } else {

      this.prior(args, callback)

    }
  }

  this._executeSavePermissionsWrapper = function(args, callback) {

    if(args.perm$) {

      debug(JSON.stringify(args))
      self._executeSavePermissions(args, callback)

    } else {

      this.prior(args, callback)

    }
  }

  this._executeListPermissionsWrapper = function(args, callback) {

    if(args.perm$) {

      debug(JSON.stringify(args))
      self._executeListPermissions(args, callback)

    } else {

      this.prior(args, callback)

    }
  }
}

ACLMicroservicesBuilder.prototype.register = function(aclDefinition) {


  for(var i = 0 ; i < aclDefinition.entities.length ; i++) {
    var actions = aclDefinition.actions
    for(var j = 0 ; j < actions.length ; j++) {

      var argsMatching = _.clone(aclDefinition.entities[i])

      argsMatching.role = 'entity'

      // TODO: differentiate create from update
      switch(actions[j]) {
        case 'save':
          argsMatching.cmd = 'save'
          break
        case 'load':
          argsMatching.cmd = 'load'
          break
        case 'list':
          argsMatching.cmd = 'list'
          break
        case 'remove':
          argsMatching.cmd = 'remove'
          break
        default:
          throw new Error('unsupported action ['+actions[j]+'] in ' + JSON.stringify(aclDefinition))
      }

      var aclProcedure = this._ACLProcedureResolver.find(argsMatching)

      if(!aclProcedure) {
        aclProcedure = new AccessControlProcedure()
        this._ACLProcedureResolver.add(argsMatching, aclProcedure)
      }

      aclProcedure.addAccessControls(aclDefinition)
    }
  }

}

ACLMicroservicesBuilder.prototype.augmentSeneca = function(seneca) {

  var filterList = this._ACLProcedureResolver.list()
  for(var i = 0 ; i < filterList.length ; i++) {

    switch(filterList[i].match.cmd) {
      case 'load':
        seneca.add(filterList[i].match, this._executeReadPermissionsWrapper)
        break
      case 'save':
        seneca.add(filterList[i].match, this._executeSavePermissionsWrapper)
        break
      case 'list':
        seneca.add(filterList[i].match, this._executeListPermissionsWrapper)
        break
      default:
        console.warn('command [' + filterList[i].match.cmd + '] is not implemented')
    }

  }
}

ACLMicroservicesBuilder.prototype._executeReadPermissions = function(args, callback) {
  var self = this
  var roles = extractRoles(args)
  var context = extractContext(args)
  var entityDef = extractEntityDef(args)

  delete args.perm$

  this._seneca.act(args, function(err, entity) {

    if(err) {
      callback(err, undefined)
    } else {

      self._deepReadAuthorize(entityDef, entity, args.cmd, roles, context, function(err, entity) {
        callback(err, entity)
      })

    }

  })
}

ACLMicroservicesBuilder.prototype._executeListPermissions = function(args, callback) {
  var self = this
  var roles = extractRoles(args)
  var context = extractContext(args)
  var entityDef = extractEntityDef(args)

  delete args.perm$

  this._seneca.act(args, function(err, entities) {

    if(err) {
      callback(err, undefined)
    } else if(entities && entities.length > 0) {

      var filteredEntities = []
      var callbackCount = 0
      var stopAll = false

      // this closure is evil
      function processAuthResultForEntity(err, entity) {

        if(stopAll) return

        if(err && err.code !== ACL_ERROR_CODE) {
          stopAll = true
          callback(err, undefined)
        } else {

          if(entity) {
            filteredEntities.push(entity)
          }
          callbackCount ++
          if(callbackCount === entities.length) {
            callback(undefined, filteredEntities)
          }
        }
      }

      for(var i = 0 ; i < entities.length ; i++) {
        self._deepReadAuthorize(entityDef, entities[i], args.cmd, roles, context, processAuthResultForEntity)
      }

    } else {
      callback(undefined, [])
    }

  })
}

ACLMicroservicesBuilder.prototype._executeSavePermissions = function(args, callback) {
  var self = this


  var roles = extractRoles(args)
  var context = extractContext(args)
  var entityDef = extractEntityDef(args)

  if(args.ent.id) { // update

    console.log(args)

    this._loadAndExecuteReadPermissions(entityDef, args.ent.id, args.cmd, roles, context, function(err, entity) {

      if(err) {

        callback(err, undefined)

      } else {

        // also execute permission checks on the new attributes
        self._deepReadAuthorize(entityDef, args.ent, args.cmd, roles, context, function(err, entity) {

          if(err) {

            callback(err, undefined)

          } else {

            delete args.perm$

            self._seneca.act(args, function(err, entity) {
              callback(err, args)
            })
          }

        })
      }
    })

  } else { // create

    self._deepReadAuthorize(entityDef, args.ent, args.cmd, roles, context, function(err, entity) {

      if(err) {
        callback(err, undefined)
      } else {

        delete args.perm$

        self._seneca.act(args, function(err, entity) {
          callback(err, entity)
        })
      }

    })
  }

}

ACLMicroservicesBuilder.prototype._loadAndExecuteReadPermissions = function(entityDef, entityId, action, roles, context, callback) {

  var self = this

  var ent = this._seneca.make(canonize(entityDef))

  console.log('********* loading', entityId, ' ', entityDef)
  ent.load$(entityId, function(err, entity) {
    if(err || !entity) {
      console.log(err, entity)
      return callback(err, null)
    }
    console.log('********* loaded', entityId, ' ', entity)
    self._deepReadAuthorize(entityDef, entity, action, roles, context, function(err, entity) {
      callback(err, entity)
    })
  })
}

ACLMicroservicesBuilder.prototype._deepReadAuthorize = function(entityDef, entity, action, roles, context, callback) {
  var self = this

  var mapping = _.clone(entityDef)
  mapping.role = 'entity'
  mapping.cmd = 'load'

  var aclProcedure = self._ACLProcedureResolver.find(mapping)

  debug('_deepReadAuthorize', action, roles, aclProcedure ? 'with procedure' : 'no procedure')
  if(aclProcedure) {
    aclProcedure.authorize(entity, action, roles, context, function(err, authDecision) {
      if(err) {
        callback(err, undefined)
      } else {
        debug('_deepReadAuthorize decision', JSON.stringify(authDecision))
        var inheritDetails = inherit(authDecision)
        if(inheritDetails) {

          // TODO: log
          self._loadAndExecuteReadPermissions(inheritDetails.entity, inheritDetails.id, action, roles, context, function(err, inheritedEntity) {

            if(err) {
              callback(err, undefined)
            } else {
              callback(undefined, entity)
            }

          })

        } else if(authDecision.authorize) {

          //TODO: log auth granted
          callback(undefined, entity)

        } else {

          // TODO: log
          callback(error(authDecision), undefined)
        }

      }
    })
  } else {
    console.log('no acls for', JSON.stringify(mapping))
    callback(undefined, entity)
  }
}

function error(authDecision) {
  var err = new Error('Permission Denied')
  err.reason = authDecision
  err.code = ACL_ERROR_CODE
  err.status = 401
  err.toString = selfErrorString
  return err
}

function selfErrorString() {
  var str = this.message
  str += '\n[' + this.code + '|' + this.status + ']\n'
  str += JSON.stringify(this.reason)
  return str
}

function extractRoles(args) {
  return args.perm$.roles
}

function extractContext(args) {
  return {
    user: args.user$
  }
}

function extractEntityDef(args) {
  return {
    zone: args.zone,
    base: args.base,
    name: args.name
  }
}

function canonize(entityDef) {
  return (entityDef.zone || '-') + '/' + (entityDef.base || '-') + '/' + entityDef.name
}

function inherit(authDecision) {
  if(authDecision.authorize && authDecision.inherit && authDecision.inherit.length > 0) {
    return authDecision.inherit[0]
  }
  return false
}

ACLMicroservicesBuilder.ACL_ERROR_CODE = ACL_ERROR_CODE


module.exports = ACLMicroservicesBuilder
