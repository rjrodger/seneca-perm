/* Copyright (c) 2013-2014 Richard Rodger, MIT License */
'use strict'

var _ = require('lodash')

// var AccessControlProcedure = require('access-controls')

var ACLMicroservicesBuilder = require('./lib/acl-microservices-builder')

var name = 'perm'
var error = require('eraro')({
  package: name
})


// TODO: should be able to dynamically add perms so they can be used from custom plugins


module.exports = function (options) {
  var seneca = this

  var aclBuilder = new ACLMicroservicesBuilder(seneca)

  options = this.util.deepextend({
    status: {
      denied: 401
    },
    anon: {}
  }, options)

  function buildACLs () {
    if (options.accessControls) {
      var allowedProperties = buildPropertiesMap(options.allowedProperties)
      aclBuilder.register(options.accessControls, allowedProperties)
      aclBuilder.augmentSeneca(seneca)
    }
  }

  function buildPropertiesMap (properties) {
    var allowedProperties = {}
    if (properties) {
      for (var i = 0; i < properties.length; i++) {
        var key = canonize(properties[i].entity)
        allowedProperties[key] = properties[i].fields
      }
    }
    return allowedProperties
  }

  function getAction (args) {
    var action
    // TODO: replace with hash
    switch (args.cmd) {
      case 'save':
        action = args.ent.id ? 'u' : 'c'
        break
      case 'delete':
        action = 'd'
        break
      case 'load':
      case 'list':
        action = 'r'
        break
    }
    return action
  }


  var denied = options.status.denied

  function proceed (allow, type, meta, args, parent, respond) {
    if (!allow) {
      return respond(error('perm/fail/' + type, 'Not Allowed.', {
        args: args,
        status: denied
      }))
    }
    parent(args, respond)
  }

  function allow_ent_op (args, opspec) {
    opspec = void 0 === opspec ? '' : opspec
    var ops = ''

    if ('save' === args.cmd) {
      ops = args.ent.id ? 'u' : 'c'
    }
    else if ('load' === args.cmd) {
      ops = args.q.id ? 'r' : 'rq'
    }
    else if ('remove' === args.cmd) {
      ops = args.q.id ? 'd' : 'dq'
    }
    else if ('list' === args.cmd) {
      ops = 'q'
    }

    var allow = '*' === opspec
    if (!allow) {
      _.each(ops.split(''), function (op) {
        allow = ~opspec.indexOf(op) || allow
      })
    }

    return {allow: !!allow, need: ops, has: opspec}
  }

  function canonize (entityDef) {
    return (entityDef.zone || '-') + '/' + (entityDef.base || '-') + '/' + entityDef.name
  }

  function permcheck (args, respond) {
    var seneca = this
    var prior = this.prior
    if (!prior) {
      return respond(error('perm/no-prior', 'Prior does not exist', {args: args}))
    }

    var perm = args.perm$
    var user = args.user$

    // TODO: all permissions should be checked to reach a consensus:
    //         either all checks grant permission or one of them denies it
    if (perm) {
      if (_.isBoolean(perm.allow)) {
        return proceed(perm.allow, 'allow', null, args, prior, respond)
      }
      else if (perm.act) {
        var allow = !!perm.act.find(args)
        return proceed(allow, 'act', null, args, prior, respond)
      }
      else if (perm.roles) {
        // FIXME
        var action = getAction(args)

        var entityDef = {
          zone: args.zone,
          base: args.base,
          name: args.name
        }
        acls.executePermissions(seneca, args, prior, respond)
      }
      else if (perm.entity) {
        var opspec = perm.entity.find(args)

        var result = allow_ent_op(args, opspec)
        return proceed(result.allow, 'entity/operation', {allowed: opspec, need: result.need}, args, prior, respond)
      }
      else if (perm.own) {
        var opspec = perm.own.entity.find(args)
        var owner = perm.own.owner
        var result = allow_ent_op(args, opspec)

        if (!result.allow) {
          return respond(error('perm/fail/own', 'not allowed', {
            allowed: opspec,
            need: result.need,
            args: args,
            status: denied
          }))
        }

        if ('save' === args.cmd || 'load' === args.cmd || 'remove' === args.cmd) {
          var ent = args.ent
          var id = 'load' === args.cmd ? (args.q && args.q.id) : ent.id


          // automatically set owner field
          if ('save' === args.cmd) {
            ent.owner = owner
          }

          if (id) {
            var checkent = seneca.make(ent.canon$({object$: true}))
            checkent.load$(id, function (err, existing) {
              if (err) return respond(err)

              if (existing && existing.owner !== owner) {
                return respond(error('perm/fail/own', 'Not owner of the resource',
                  {owner: owner, args: args, status: denied}))
              }

              return prior(args, respond)
            })
          }
          else {
            // load with query
            if (args.q) {
              args.q.owner = owner
            }
            ent.owner = owner
            return prior(args, respond)
          }
        }
        else {
          args.q.owner = owner
          return prior(args, respond)
        }
      }
      else return respond(error('perm/no-match', 'Permission don not match', {args: args}))
    }

    // need an explicit perm$ arg to trigger a permcheck
    // this allows internal operations to proceed as normal
    else {
      return prior(args,respond)
    }
  }

  buildACLs()

  seneca.add({init: name}, function (args, respond) {
    if (_.isBoolean(options.act) && options.act) {
      _.each(seneca.list(), function (act) {
        seneca.add(act, permcheck)
      })
    }
    else if (_.isArray(options.act)) {
      _.each(options.act, function (pin) {
        seneca.add(pin, permcheck)
      })
    }

    var cmds = ['save', 'load', 'list', 'remove']

    options.entity = _.isBoolean(options.entity) ? (options.entity ? ['-/-/-'] : []) : (options.entity || [])

    _.each(options.entity, function (entspec) {
      _.each(cmds, function (cmd) {
        entspec = _.isString(entspec) ? seneca.util.parsecanon(entspec) : entspec
        var spec = _.extend({role: 'entity', cmd: cmd}, entspec)

        seneca.add(spec, permcheck)
      })
    })

    options.own = _.isBoolean(options.own) ? (options.own ? ['-/-/-'] : []) : (options.own || [])

    _.each(options.own, function (entspec) {
      _.each(cmds, function (cmd) {
        entspec = _.isString(entspec) ? seneca.util.parsecanon(entspec) : entspec
        var spec = _.extend({role: 'entity', cmd: cmd}, entspec)
        seneca.add(spec, permcheck)
      })
    })

    respond()
  })

  function makeperm (permspec) {
    if (permspec.ready) {
      return permspec
    }

    var perm = {
      ready: true,
      toString: function () {
        return 'perm: ' +
          'allow: ' + this.allow + ', ' +
          'act: ' + (this.act ? this.act.toString() : '') + ', ' +
          'entity: ' + (this.entity ? this.entity.toString() : '') + ', ' +
          'own: ' + (this.own ? this.own.entity.toString() + ' (owner:' + this.own.owner + ')' : '')
      }
    }

    if (permspec.allow) {
      perm.allow = !!permspec.allow
    }


    function make_router (permspec, name) {
      var router = seneca.util.router()

      var pinspec = permspec[name]
      if (_.isArray(pinspec)) {
        _.each(pinspec, function (entry) {
          if (_.isUndefined(entry.perm$)) {
            throw error('perm/no-perm-defined', 'No permission was defined', {entry: entry})
          }

          var opspec = entry.perm$
          var typespec = seneca.util.clean(_.clone(entry))
          router.add(typespec, opspec)
        })
      }
      else if (_.isObject(pinspec) && ('entity' === name || 'own' === name)) {
        _.each(pinspec, function (perm$, canonstr) {
          router.add(seneca.util.parsecanon(canonstr), perm$)
        })
      }

      perm[name] = router
    }

    if (permspec.act) {
      make_router(permspec, 'act')
    }
    if (permspec.entity) {
      make_router(permspec, 'entity')
    }
    if (permspec.roles) {
      perm.roles = permspec.roles
    }
    if (permspec.own) {
      make_router(permspec, 'own')
      var entity = perm.own
      perm.own = {
        entity: entity,
        owner: permspec.owner
      }
    }

    return perm
  }


  var nilperm = makeperm({})
  var anonperm = makeperm(options.anon)

  seneca.add({role: name, cmd: 'makeperm'}, function (args, respond) {
    var perm = makeperm(args.perm)
    respond(null, perm)
  })

  function service (req, res, next) {
    if (req.seneca.user) {
      var user = req.seneca.user
      if (user.admin) {
        // don't make perm checks
        return next()
      }
      else {
        var perm = nilperm
        if (user.perm) {
          perm = makeperm(user.perm)
        }
        else {
          user.perm = {}
        }
        user.perm.owner = user.id
        res.seneca = req.seneca = req.seneca.delegate({perm$: perm, user$: user})
        req.seneca.user = user

        return next()
      }
    }
    else {
      res.seneca = req.seneca = req.seneca.delegate({perm$: anonperm})
      return next()
    }
  }

  return {
    name: name,
    exports: {
      make: makeperm
    }
  }
}
