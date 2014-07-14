
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

  this._executeRemovePermissionsWrapper = function(args, callback) {
    if(args.perm$) {

      debug(JSON.stringify(args))
      self._executeRemovePermissions(args, callback)

    } else {

      this.prior(args, callback)

    }
  }
}

ACLMicroservicesBuilder.prototype.register = function(accessControls) {
  this._ACLProcedureResolver = AccessControlProcedure.generateActionsMapping(accessControls)
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
  var context = extractContext(args)
  var entityDef = extractEntityDef(args)

  delete args.perm$

  if(args.q.id) {

    this._loadAndAuthorize(entityDef, args.q.id, args.cmd, roles, context, function(err, dbEntity) {

      if(err) {

        callback(err, undefined)

      } else {

        self._seneca.act(args, function(err, entity) {
          if(err) {
            return callback(err, undefined)
          }
          // the entity returned by the remove needs to be filtered again
          self._filter(entityDef, entity, 'load', roles, context, function(err, entity) {
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
  var context = extractContext(args)
  var entityDef = extractEntityDef(args)

  delete args.perm$

  this._seneca.act(args, function(err, entity) {

    if(err || !entity) {
      callback(err, undefined)
    } else {
      // console.log('ENTITY', entity)
      // console.log('CONTEXT', context)
      self._deepAuthorize(entityDef, entity, args.cmd, args.cmd, roles, context, true, function(err, entity) {
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
        self._deepAuthorize(entityDef, entities[i], args.cmd, args.cmd, roles, context, true, processAuthResultForEntity)
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

    this._loadAndAuthorize(entityDef, args.ent.id, args.cmd, roles, context, function(err, dbEntity) {

      if(err) {

        callback(err, undefined)

      } else {

        // also execute permission checks on the new attributes
        self._deepAuthorize(entityDef, args.ent, args.cmd, 'save_new', roles, context, true, function(err, filteredEntity) {

          if(err) {

            callback(err, undefined)

          } else {

            merge(dbEntity, args.ent)

            delete args.perm$

            self._seneca.act(args, function(err, entity) {
              if(err) {
                return callback(err, undefined)
              }
              // the entity returned by the save needs to be filtered again
              self._filter(entityDef, entity, 'load', roles, context, function(err, entity) {
                callback(err, entity)
              })

            })
          }

        })
      }
    })

  } else { // create

    self._deepAuthorize(entityDef, args.ent, args.cmd, 'save_new', roles, context, true, function(err, filteredEntity) {

      if(err) {
        callback(err, undefined)
      } else {

        delete args.perm$

        self._seneca.act(args, function(err, entity) {
          if(err) {
            return callback(err, undefined)
          }
          // the entity returned by the save needs to be filtered again
          self._filter(entityDef, entity, 'load', roles, context, function(err, entity) {
            callback(err, entity)
          })
        })
      }

    })
  }

}

ACLMicroservicesBuilder.prototype._loadAndAuthorize = function(entityDef, entityId, action, roles, context, callback) {

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

    self._deepAuthorize(entityDef, dbEntity, action, ruleAction, roles, context, false, function(err, entity) {
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

ACLMicroservicesBuilder.prototype._deepAuthorize = function(entityDef, entity, action, ruleAction, roles, context, applyFilters, callback) {
  var self = this

  var aclProcedure = AccessControlProcedure.getProcedureForEntity(self._ACLProcedureResolver, entityDef, action)

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
          self._loadAndAuthorize(inheritDetails.entity, inheritDetails.id, action, roles, context, function(err, inheritedEntity) {

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
          callback(error(self._seneca, authDecision), undefined)
        }

      }
    })
  } else {
    console.log('no acls for', JSON.stringify(entityDef), action)
    callback(undefined, entity)
  }
}

function error(seneca, authDecision) {
  var err = new Error('Permission Denied')
  err.reason = authDecision
  err.code = ACL_ERROR_CODE
  err.status = 401
  err.httpstatus = 401
  err.seneca = seneca
  err.toString = selfErrorString
  return err
}

function selfErrorString() {
  var jsonReadyError = {
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
