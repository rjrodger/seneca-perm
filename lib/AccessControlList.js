
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
  var shouldApply = {
    ok: true
  }

  if(!this._actionMatch(action)) {
    shouldApply.ok = false
    shouldApply.reason = 'action does not match'
  }

  return shouldApply
}

AccessControlList.prototype._actionMatch = function(intendedAction) {
  return this._actions[intendedAction] === true
}

/**
 * returns:
 * - obj.ok=true if the rule should apply and the conditions match the context
 * - obj.ok=false if the rule should apply and the conditions don't match the context (access denied)
 * - obj.ok=undefined if the conditions don't match the object (rule should not apply)
 */
AccessControlList.prototype._conditionsMatch = function(obj, context) {
  for(var i = 0 ; i < this._conditions.length ; i++) {
    var condition = this._conditions[i]
    var match = this._conditionMatch(condition, obj, context)
    if(match.ok === false) {
      return match
    } else if(match.ok === undefined){
      return match
    }
  }
  return {
    ok: true
  }
}

AccessControlList.prototype._conditionMatch = function(condition, obj, context) {
  var match = {ok: true}
  if(condition.attributes) {

    for(var attr in condition.attributes) {

      if(condition.attributes.hasOwnProperty(attr)) {
        var expectedValue = condition.attributes[attr]
        var actualValue = this._objectParser.lookup(attr, obj)
        if(this._objectParser.isTemplate(expectedValue)) {
          var expectedValue = this._objectParser.lookupTemplate(expectedValue, context)
          if(expectedValue !== actualValue) {
            match.ok = false
            match.reason = 'Attr ['+attr+'] should be ['+expectedValue+'] but is ['+actualValue+']'
          }
        } else if(actualValue !== expectedValue) {
          match.ok = undefined // this ACL should not apply to this object
          match.reason = 'Condition do not apply. Attr ['+attr+'] should be ['+expectedValue+'] but is ['+actualValue+']'
          return match
        }
      }
    }
  }
  return match
}

AccessControlList.prototype.authorize = function(obj, action, roles, context, callback) {
  var authorize = false
  var reason = ''
  var shouldApply = this.shouldApply(obj, action)
  if(shouldApply.ok) {

      var conditionsMatch = this._conditionsMatch(obj, context)

      if(conditionsMatch.ok === false) {

        authorize = false
        reason = conditionsMatch.reason

      } else if(conditionsMatch.ok === true) {

        var rolesMatch = this._rolesMatch(this._roles, roles)
        authorize = rolesMatch.ok
        reason    = rolesMatch.reason

      } else {
        // conditions say this ACL does not apply
        authorize = true
        reason    = conditionsMatch.reason
      }
  } else {
    reason    = shouldApply.reason
    authorize = true
  }

  setImmediate(function() {
    callback(undefined, {authorize: authorize, reason: reason})
  })
}

AccessControlList.prototype._rolesMatch = function(expectedRoles, actualRoles) {
  var rolesMatch = {ok: true}
  var missingRoles = []
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
        missingRoles.push(expectedRoles[i])
      }
    }
  } else {
    // TODO: handle inheritance
  }

  if(missingRoles.length > 0) {

     rolesMatch.ok = false
     rolesMatch.reason = 'expected roles ' + JSON.stringify(expectedRoles) +
       ' but got roles ' + JSON.stringify(actualRoles) +
       '. missing roles ' + JSON.stringify(missingRoles)
   }

  return rolesMatch
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
