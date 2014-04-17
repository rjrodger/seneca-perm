var _ = require('underscore')
var ACL = require('../lib/AccessControlList.js')

/** An access control procedure runs a set of ACLs against a given pair of <entity> and <action>
 */
function AccessControlProcedure(acls) {

  this._accessControls = []
  if(acls) {
    this.addAccessControls(acls)
  }

}

AccessControlProcedure.prototype.addAccessControls = function(acl) {
  if(_.isArray(acl)) {
    for(var i = 0 ; i < acl.length ; i++) {
      this.addAccessControls(acl[i])
    }
  } else if(_.isObject(acl)){
    this._accessControls.push(new ACL(acl))
  } else {
    throw new Error('unsuported ACL object type: ' + typeof acl)
  }
}

AccessControlProcedure.prototype.authorize = function(obj, action, roles, context, callback) {
  //console.log('Running authorization procedure', obj, action, roles)

  this._nextACL(obj, action, roles, this._accessControls.slice(0), context, undefined, function(err, details) {
    callback(err, details)
  })
}

AccessControlProcedure.prototype._nextACL = function(obj, action, roles, accessControls, context, details, callback) {
  if(!details) {
    details = {authorize: true}
  }
  if(!details.history) {
    details.history = []
  }
  if(!details.inherit) {
    details.inherit = []
  }
  var self = this

  if(accessControls && accessControls.length > 0) {
    var accessControl = accessControls.shift()
    var shouldApply = accessControl.shouldApply(obj, action)
    if(shouldApply.ok) {
      //console.log('running authorization service', accessControl.name())
      accessControl.authorize(obj, action, roles, context, function(err, result) {

        details.history.push({
          service: accessControl.name(),
          authorize: result ? result.authorize : null,
          control: accessControl.control(),
          err: err || null,
          reason: result ? result.reason : null
        })

        if(err || !result) {
          details.authorize = false
          callback(err, details)
        }

        if(result.inherit) {
          details.inherit = details.inherit.concat(result.inherit)
        }

        var stop = false

        switch(accessControl.control()) {
          case 'requisite':
            if(!result.authorize) {
              details.authorize = false
              stop = true
            }
            break
          case 'required':
            if(!result.authorize) {
              details.authorize = result.authorize
            }
            break
          case 'sufficient':
            if(result.authorize) {
              details.authorize = true
              stop = true
            }
            break
        }

        if(stop) {
          callback(undefined, details)
        } else {
          self._nextACL(obj, action, roles, accessControls, context, details, callback)
        }
      })
    } else {
      //console.log('ignoring authorization service', accessControl.name(), '. reason:', shouldApply.reason)
      self._nextACL(obj, action, roles, accessControls, context, details, callback)
    }
  } else {
    callback(undefined, details)
  }
}

module.exports = AccessControlProcedure
