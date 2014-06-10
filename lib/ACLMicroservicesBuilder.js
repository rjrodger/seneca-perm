
var patrun = require('patrun')
var _ = require('lodash')
var AccessControlProcedure = require('access-controls')

function ACLMicroservicesBuilder(seneca) {
  this._ACLProcedureResolver = patrun()
  this._seneca = seneca

  var self = this

  this._executeReadPermissionsWrapper = function(args, callback) {

    if(args.perm$) {

      self._executeReadPermissions(args, callback)

    } else {

      this.prior(args, callback)

    }
  }

  this._executeSavePermissionsWrapper = function(args, callback) {

    if(args.perm$) {

      self._executeSavePermissions(args, callback)

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
        case 'c':
        case 'u':
          argsMatching.cmd = 'save'
          break
        case 'r':
          argsMatching.cmd = 'load'
          break
        case 'q':
          argsMatching.cmd = 'list'
          break
        case 'd':
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
      case 'read':
        seneca.add(filterList[i].match, this._executeReadPermissionsWrapper)
        break
      case 'save':
        seneca.add(filterList[i].match, this._executeSavePermissionsWrapper)
        break
    }

  }
}

ACLMicroservicesBuilder.prototype._executeReadPermissions = function(args, callback) {
  var self = this
  var roles = extractRoles(args)
  var context = extractContext(args)

  delete args.perm$

  this._seneca.act(args, function(err, entity) {

    if(err) {
      callback(err, undefined)
    } else {

      self._deepReadAuthorize(entity, args.cmd, roles, context, function(err, entity) {
        callback(err, entity)
      })

    }

  })
}

ACLMicroservicesBuilder.prototype._executeSavePermissions = function(args, callback) {
  var self = this
  if(args.ent.id) { // update

    var roles = extractRoles(args)
    var context = extractContext(args)

    var entityDef = canonize(args.ent.entity$)

    this._loadAndExecuteReadPermissions(entityDef, args.ent.id, args.cmd, roles, context, function(err, entity) {

      if(err) {

        callback(err, undefined)

      } else {

        self._deepReadAuthorize(args.ent, args.cmd, roles, context, function(err, entity) {

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

    self._deepReadAuthorize(args.ent, args.cmd, roles, context, function(err, entity) {

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

  ent.load$(entityId, function(err, entity) {
    if(err || !entity) {
      return callback(err, null)
    }
    self._deepReadAuthorize(entity, action, roles, context, function(err, entity) {
      callback(err, entity)
    })
  })
}

ACLMicroservicesBuilder.prototype._deepReadAuthorize = function(entity, action, roles, context, callback) {
  var self = this

  var mapping = this._seneca.util.parsecanon(entity.entity$)
  mapping.role = 'entity'
  mapping.cmd = 'load'

  var aclProcedure = self._ACLProcedureResolver.find(mapping)

  if(aclProcedure) {
    aclProcedure.authorize(entity, action, roles, context, function(err, authDecision) {
      if(err) {
        callback(err, undefined)
      } else {
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
  err.code = 'perm/fail/acl'
  err.status = 401
  return err
}

function extractRoles(args) {
  return args.perm$.roles
}

function extractContext(args) {
  return {
    user: args.user$
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


module.exports = ACLMicroservicesBuilder
