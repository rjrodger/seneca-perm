
var _ = require('lodash')
var AccessControlProcedure = require('access-controls')

var DEBUG = false

var ACL_ERROR_CODE = 'perm/fail/acl'

function debug() {
  if(DEBUG) {
    console.log.apply(console, arguments)
  }
}

function ACLMicroservicesBuilder(seneca) {
  this._ACLProcedureResolver = undefined
  this._seneca = seneca
  this._allowedProperties = {};

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

      this.ACLMicroservicesBuilder = self;
      self._executeSavePermissions.call(this, args, callback)

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

  this._executeRemovePermissionsWrapper = function(args, callback) {
    if(args.perm$) {

      this.ACLMicroservicesBuilder = self;
      self._executeRemovePermissions.call(this, args, callback)

    } else {

      this.prior(args, callback)

    }
  }
}

ACLMicroservicesBuilder.prototype.register = function(accessControls, properties) {
  this._ACLProcedureResolver = AccessControlProcedure.generateActionsMapping(accessControls)
  this._allowedProperties = properties;
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
      case 'remove':
        seneca.add(filterList[i].match, this._executeRemovePermissionsWrapper)
        break
      default:
        console.warn('Permissions: command [' + filterList[i].match.cmd + '] is not implemented but is used in an ACL rule.')
    }

  }
}

ACLMicroservicesBuilder.prototype._executeRemovePermissions = function(args, callback) {
  var self = this

  var roles = extractRoles(args)
  debug('ACLMicroservicesBuilder.prototype._executeRemovePermissions, roles: %s', roles);
  var context = extractContext(args)
  var entityDef = extractEntityDef(args)

  delete args.perm$

  if(args.q.id) {

    this.ACLMicroservicesBuilder._loadAndAuthorize(entityDef, args.q.id, args.cmd, roles, context, args.showSoftDenied$, function(err, dbEntity) {

      if(err) {

        callback(err, undefined)

      } else {

        self.prior(args, function(err, entity) {
          if(err) {
            return callback(err, undefined)
          }
          // the entity returned by the remove needs to be filtered again
          self.ACLMicroservicesBuilder._filter(entityDef, entity, 'load', roles, context, function(err, entity) {
            callback(err, entity)
          })
        })

      }
    })

  } else {
    var err = new Error('ACL permissions deny multi delete. A query id is required')
    callback(err, undefined)
  }

}

ACLMicroservicesBuilder.prototype._executeReadPermissions = function(args, callback) {
  var self = this
  var roles = extractRoles(args)
  debug('ACLMicroservicesBuilder.prototype._executeReadPermissions, roles: %s', roles);
  var context = extractContext(args)
  var entityDef = extractEntityDef(args)

  delete args.perm$

  this._seneca.act(args, function(err, entity) {

    if(err || !entity) {
      callback(err, undefined)
    } else {
      // console.log('ENTITY', entity)
      // console.log('CONTEXT', context)
      self._deepAuthorize(entityDef, entity, args.cmd, args.cmd, roles, context, true, args.showSoftDenied$, function(err, entity) {
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
        self._deepAuthorize(entityDef, entities[i], args.cmd, args.cmd, roles, context, true, args.showSoftDenied$, processAuthResultForEntity)
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

  delete args.perm$

  if(args.ent.id) { // update

    self.ACLMicroservicesBuilder._loadAndAuthorize(entityDef, args.ent.id, args.cmd, roles, context, args.showSoftDenied$, function(err, dbEntity) {

      if(err) {

        callback(err, undefined)

      } else {

        // also execute permission checks on the new attributes
        self.ACLMicroservicesBuilder._deepAuthorize(entityDef, args.ent, args.cmd, 'save_new', roles, context, true, args.showSoftDenied$, function(err, filteredEntity) {

          if(err) {

            callback(err, undefined)

          } else {

            merge(dbEntity, args.ent)

            delete args.perm$

            self.prior(args, function(err, entity) {
              if(err) {
                return callback(err, undefined)
              }

              // the entity returned by the save needs to be filtered again
              self.ACLMicroservicesBuilder._filter(entityDef, entity, 'load', roles, context, function(err, entity) {
                callback(err, entity)
              })

            })
          }

        })
      }
    })

  } else { // create

    self.ACLMicroservicesBuilder._deepAuthorize(entityDef, args.ent, args.cmd, 'save_new', roles, context, true, args.showSoftDenied$, function(err, filteredEntity) {

      if(err) {
        callback(err, undefined)
      } else {

        delete args.perm$

        self.prior(args, function(err, entity) {
          if(err) {
            return callback(err, undefined)
          }
          // the entity returned by the save needs to be filtered again
          self.ACLMicroservicesBuilder._filter(entityDef, entity, 'load', roles, context, function(err, entity) {
            callback(err, entity)
          })
        })
      }

    })
  }

}

ACLMicroservicesBuilder.prototype._loadAndAuthorize = function(entityDef, entityId, action, roles, context, showSoftDenied, callback) {

  var self = this

  var ent = this._seneca.make(canonize(entityDef))

  ent.load$(entityId, function(err, dbEntity) {
    if(err || !dbEntity) {
      return callback(err, null)
    }

    if(action === 'save') {
      var ruleAction = 'save_existing'
    } else {
      ruleAction = action
    }

    self._deepAuthorize(entityDef, dbEntity, action, ruleAction, roles, context, false, showSoftDenied, function(err, entity) {
      callback(err, err ? undefined : dbEntity)
    })
  })
}

ACLMicroservicesBuilder.prototype._filter = function(entityDef, entity, action, roles, context, callback) {
  var aclProcedure = AccessControlProcedure.getProcedureForEntity(this._ACLProcedureResolver, entityDef, action)
  if(aclProcedure) {
    aclProcedure.authorize(entity, action, roles, context, function(err, authDecision) {
      if(err) {
        callback(err, undefined)
      } else {
        aclProcedure.applyFilters(authDecision.filters, entity, action)
        callback(undefined, entity)
      }
    })
  } else {
    setImmediate(function() {
      callback(undefined, entity)
    })
  }
}

ACLMicroservicesBuilder.prototype._deepAuthorize = function(entityDef, entity, action, ruleAction, roles, context, applyFilters, showSoftDenied, callback) {
  var self = this

  var aclProcedure = AccessControlProcedure.getProcedureForEntity(self._ACLProcedureResolver, entityDef, action)

  var allowedProperties = this._allowedProperties

  var allowedFields = [];
  var entityString = canonize(entityDef)

  if(allowedProperties[entityString]) {
    allowedFields = allowedProperties[entityString]
  }

  debug('_deepAuthorize', action, entityDef, 'id=', entity.id, 'roles=', roles, aclProcedure ? 'with procedure' : 'no procedure')
  if(aclProcedure) {
    aclProcedure.authorize(entity, ruleAction, roles, context, function(err, authDecision) {
      if(err) {
        callback(err, undefined)
      } else {
        //console.log(JSON.stringify(authDecision, null, 2))
        debug('_deepAuthorize decision', JSON.stringify(authDecision))
        var inheritDetails = inherit(authDecision)

        if(applyFilters) {
          aclProcedure.applyFilters(authDecision.filters, entity, action)
        }
        
        if(inheritDetails) {

          // TODO: log
          self._loadAndAuthorize(inheritDetails.entity, inheritDetails.id, action, roles, context, showSoftDenied, function(err, inheritedEntity) {

            if(err) {
              callback(err, undefined)
            } else {
              callback(undefined, entity)
            }

          })

        } else if(authDecision.authorize) {
          //TODO: log auth granted
          callback(undefined, entity)

        } else if(!authDecision.authorize && !authDecision.hard && showSoftDenied) {
          entity = removeEntityFields(allowedFields, entity)
          callback(undefined, entity)
        } else {
          // TODO: log
          callback(error(self._seneca, authDecision), undefined)
        }

      }
    })
  } else {
    debug('no acls for', JSON.stringify(entityDef), action)
    callback(undefined, entity)
  }
}

function error(seneca, authDecision) {
  var message = 'Permission Denied'
  if(authDecision.summary && authDecision.summary.length > 0) {
    message = ''
    for(var i = 0 ; i < authDecision.summary.length; i++) {
      message += authDecision.summary[i].reason + '\n'
    }
  }
  var err = new Error(message)
  err.summary = authDecision.summary
  err.details = authDecision
  err.code = ACL_ERROR_CODE
  err.status = 403
  err.httpstatus = 403
  err.seneca = seneca
  err.toString = selfErrorString
  return err
}

function removeEntityFields(allowedFields, entity) {
  if(allowedFields.length > 0) {
    for(var property in entity) {
      if(entity.hasOwnProperty(property)) {
        var propertyAllowed = allowedFields.indexOf(property);
        if(propertyAllowed === -1) {
          delete entity[property];
        }
      }
    }
  }

  return entity
}

function selfErrorString() {
  var jsonReadyError = {
    summary: this.summary,
    message: this.message,
    status: this.status,
    code: this.code,
    reason: this.reason
  };
  return JSON.stringify(jsonReadyError);
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

/** Unfortunately, this is mostly for the unit tests to pass.
 * The in-memory store behaviour will completely replace an existing object with
 *   the one being saved. Hence we need to do an in-memory merge before saving.
 * Bug opened against seneca: https://github.com/rjrodger/seneca/issues/43
 */
function merge(source, destination) {
  for(var attr in source) {
    if(!destination.hasOwnProperty(attr) && !/\$$/.test(attr)) {
      destination[attr] = source[attr]
    }
  }
}

ACLMicroservicesBuilder.ACL_ERROR_CODE = ACL_ERROR_CODE


module.exports = ACLMicroservicesBuilder
