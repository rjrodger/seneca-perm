
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
}

ACLMicroservicesBuilder.prototype.register = function(aclDefinition) {


  for(var j = 0 ; j < aclDefinition.entities.length ; j++) {
    var entityDefinition = aclDefinition.entities[j]

    // TODO: also map by command (save, read, delete)
    entityDefinition.role = 'entity'
    entityDefinition.cmd = 'load'
    var aclProcedure = this._ACLProcedureResolver.find(entityDefinition)

    if(!aclProcedure) {
      aclProcedure = new AccessControlProcedure()
      this._ACLProcedureResolver.add(entityDefinition, aclProcedure)
    }
    aclProcedure.addAccessControls(aclDefinition)
  }

}

ACLMicroservicesBuilder.prototype.augmentSeneca = function(seneca) {
  var filterList = this._ACLProcedureResolver.list()
  for(var i = 0 ; i < filterList.length ; i++) {
    console.log('overriding', JSON.stringify(filterList[i].match))
    seneca.add(filterList[i].match, this._executeReadPermissionsWrapper)
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

ACLMicroservicesBuilder.prototype._loadAndExecuteReadPermissions = function(entityDef, entityId, action, roles, context, callback) {

  var self = this

  var ent = globalSeneca.make(canonize(entityDef))

  ent.load$(entityId, function(err, entity) {
    if(err) {
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
