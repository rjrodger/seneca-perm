
//   var perm = {
//     acl: {
//       roles: ['emea'],
//       control: 'required',
//       actions: 'rw',
//       conditions: [{
//           attributes: {
//             'region': 'emea'
//           }
//         }
//       ]
//     }
//   }
var assert   = require('assert')
var _        = require('underscore')
var OTParser = require('object-tree')

function AccessControlList(conf) {

  assert(conf, 'missing configuration')
  assert(conf.roles, 'roles is required')
  assert(_.isArray(conf.roles), 'roles should be a string array')

  this._roles = conf.roles
  this._name = conf.name || JSON.stringify(conf.roles)

  assert(conf.control, 'control is required')
  this._control = conf.control

  // create a map for O(1) speed
  this._actions = {}
  if(conf.actions && typeof conf.actions === 'string') {
    for(var i = 0 ; i < conf.actions.length ; i++) {
      this._actions[conf.actions[i]] = true
    }
  }

  this._conditions = conf.conditions || []

  this._objectParser = new OTParser()
}

AccessControlList.prototype.shouldApply = function(obj, action) {
  return this._actionMatch(action) && this._conditionsMatch(obj)
}

AccessControlList.prototype._actionMatch = function(intendedAction) {
  return this._actions[intendedAction] === true
}

AccessControlList.prototype._conditionsMatch = function(obj) {
  for(var i = 0 ; i < this._conditions.length ; i++) {
    var condition = this._conditions[i]
    var match = this._conditionMatch(condition, obj)
    if(!match) {
      return false
    }
  }
  return true
}

AccessControlList.prototype._conditionMatch = function(condition, obj) {
  if(condition.attributes) {

    for(var attr in condition.attributes) {

      if(condition.attributes.hasOwnProperty(attr)) {


        var actualValue = this._objectParser.lookup(attr, obj)

        if(actualValue !== condition.attributes[attr]) {
          return false
        }
      }

    }
  }
  return true
}

AccessControlList.prototype.authorize = function(obj, action, roles, callback) {
  var authorize = false

  if(this.shouldApply(obj, action)) {
    authorize = this._rolesMatch(this._roles, roles)
  } else {
    authorize = true
  }

  setImmediate(function() {
    callback(undefined, {authorize: authorize})
  })
}

AccessControlList.prototype._rolesMatch = function(expectedRoles, actualRoles) {
  if(expectedRoles && expectedRoles.length > 0) {

    // TODO: optimize this O(N square) into at least a O(N)
    for(var i = 0 ; i < expectedRoles.length ; i++) {
      var match = false
      for(var j = 0 ; j < actualRoles.length ; j++) {
        if(actualRoles[j] === expectedRoles[i]) {
          match = true
          break
        }
      }
      if(!match) {
        return false
      }
    }
  } else {
    // TODO: handle inheritance
  }
  return true
}

AccessControlList.prototype.control = function() {
  return this._control
}

AccessControlList.prototype.name = function() {
  return this._name
}

AccessControlList.prototype.toString = function() {
  return 'ACL::' + this._name
}

module.exports = AccessControlList
