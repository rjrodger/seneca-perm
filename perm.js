/* Copyright (c) 2013-2014 Richard Rodger, MIT License */
"use strict";


var util = require('util')
var patrun = require('patrun')

var _ = require('underscore')

var AccessControlProcedure = require('./lib/AccessControlProcedure.js')

var name = "perm"


// TODO: should be able to dynamically add perms so they can be used from custom plugins


module.exports = function(options) {
  var globalSeneca = this

  options = this.util.deepextend({
    status: {
      denied: 401
    },
    anon:{}
  },options)

  var entitiesACLs = patrun()

  function buildACLs() {

    if(options.accessControls) {

      for(var i = 0 ; i < options.accessControls.length ; i++) {
        var acl = options.accessControls[i]
        for(var j = 0 ; j < acl.entities.length ; j++) {
          var entity = acl.entities[j]

          // TODO: do not just push, merge
          if(!options.entity) {
            options.entity = true
          } else {
            options.entity.push((entity.zone||'-') +'/' + (entity.base||'-') + '/' +  entity.name)
          }

          var aclProcedure = entitiesACLs.find(entity)

          if(!aclProcedure) {
            aclProcedure = new AccessControlProcedure()
          }
          aclProcedure.addAccessControls(acl)

          entitiesACLs.add(acl.entities[j], aclProcedure)
        }

      }
    }
  }

  function getAction(args) {
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


  var denied = options.status.denied

  function proceed(allow,type,meta,args,parent,done) {
    if( !allow ) return globalSeneca.fail(_.extend({},meta||{},{code:'perm/fail/'+type,args:args,status:denied}),done);
    parent(args,done)
  }

  function allow_ent_op(args,opspec) {
    opspec = void 0 == opspec ? '' : opspec
    var ops = ''

    if( 'save'==args.cmd ) {
      ops = args.ent.id ? 'u' : 'c'
    }
    else if( 'load'==args.cmd ) {
      ops = args.q.id ? 'r' : 'rq'
    }
    else if( 'remove'==args.cmd ) {
      ops = args.q.id ? 'd' : 'dq'
    }
    else if( 'list'==args.cmd ) {
      ops = 'q'
    }

    var allow = '*' == opspec
    if( !allow ) {
      _.each(ops.split(''),function(op){
        allow = ~opspec.indexOf(op) || allow
      })
    }

    return {allow:!!allow,need:ops,has:opspec}
  }

  function checkACLsWithDBEntity(seneca, entityType, entityOrId, action, roles, context, callback) {

    // TODO: findall instead
    if(_.isString(entityType)) {
      entityType = seneca.util.parsecanon(entityType)
    }

    var aclAuthProcedure = entitiesACLs.find(entityType)
    if(aclAuthProcedure) {

      if(_.isObject(entityOrId)) {
        aclAuthProcedure.authorize(entityOrId, action, roles, context, function(err, details) {
          var authorized = !err && details.authorize
          seneca.log.info('inheritance authorization', authorized ? 'granted' : 'denied',
                          'for action [', action, ']',
                          'on entity [', entityType.zone + '/' + entityType.base + '/'+entityType.name, ']',
                           'acls:', details.history)

          callback(err, details)
        })
      } else {
        var ent = globalSeneca.make(canonize(entityType))

        ent.load$(entityOrId, function(err, entity) {
          if(err) {
            return callback(err, null)
          }
          aclAuthProcedure.authorize(entity, action, roles, context, function(err, details) {
            var authorized = !err && details.authorize
            seneca.log.info('inheritance authorization', authorized ? 'granted' : 'denied',
                            'for action [', action, ']',
                            'on entity [', entityType.zone + '/' + entityType.base + '/'+entityType.name, '::'+entity.id+']',
                             'acls:', details.history)

            callback(err, details)
          })
        })
      }
    } else {
      setImmediate(function() {
        callback(undefined, {
          service: 'inheritance',
          authorize: true,
          control: null,
          reason: 'ACL inheritance path directs to an entity that does not have ACLs'
        })
      })

    }
  }

  function canonize(entityDef) {
    return (entityDef.zone || '-') + '/' + (entityDef.base || '-') + '/' + entityDef.name
  }


  // TODO: move this func out of this file
  function filterAccess(seneca, aclAuthProcedure, entityOrList, action, roles, context, callback) {
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

          seneca.log.info('authorization', authDecision.authorize ? 'granted' : 'denied',
                          'for action [', action, ']',
                          'on entity [',  entity.id, ']',
                           'acls:', authDecision.history)

          if(authDecision.authorize && authDecision.inherit && authDecision.inherit.length > 0) {
            var inherit = authDecision.inherit[0]

            checkACLsWithDBEntity(seneca, inherit.entity, inherit.id, action, roles, context, function(err, inheritedAuthDecision) {

              expectedCallbackCount --

              if(inheritedAuthDecision && inheritedAuthDecision.authorize) {
                filteredList.push(entity)
              }
              if(expectedCallbackCount === 0) {
                callback(undefined, filteredList)
              }
            })
          } else if(authDecision.authorize) {
            expectedCallbackCount --
            filteredList.push(entity)
          } else {
            expectedCallbackCount --
          }

          if(expectedCallbackCount === 0) {
            callback(undefined, filteredList)
          }
        }
      }
    }

    if(_.isArray(entityOrList)) {
      if(entityOrList.length === 0) { // TODO: test this edge case
        return callback(undefined, filteredList)
      }
      expectedCallbackCount = entityOrList.length
      for(var i = 0 ; i < entityOrList.length ; i++) {
        aclAuthProcedure.authorize(entityOrList[i], action, roles, context, createEntityAccessHandler(entityOrList[i]))
      }
    } else {
      expectedCallbackCount = 1
      aclAuthProcedure.authorize(entityOrList, action, roles, context, function(err, authDecision) {
        if(err || !authDecision.authorize) {
          // TODO: proper 401 propagation
          seneca.fail({
            action: action,
            code:'perm/fail/acl',
            entity:entityOrList,
            status:denied,
            history: authDecision.history
          }, callback)
          //callback(err || new Error('unauthorized'), undefined)
        } else {
          if(authDecision.inherit && authDecision.inherit.length > 0) {

            var inherit = authDecision.inherit[0]
            checkACLsWithDBEntity(seneca, inherit.entity, inherit.id, action, roles, context, function(err, inheritedAuthDecision) {
              if(err || !inheritedAuthDecision.authorize) {
                // TODO: proper 401 propagation
                seneca.fail({
                  action: action,
                  code:'perm/fail/acl',
                  entity:entityOrList,
                  status:denied,
                  history: authDecision.history.concat(inheritedAuthDecision.history)
                }, callback)
              } else {
                callback(undefined, entityOrList)
              }
            })
          } else {

            callback(undefined, entityOrList)
          }
        }
      })
    }
  }


  function permcheck(args,done) {
    var seneca = this
    var prior = this.prior
    if( !prior ) {
      return seneca.fail({code:'perm/no-prior',args:args},done)
    }

    var perm = args.perm$
    var user = args.user$

    // TODO: all permissions should be checked to reach a consensus:
    //         either all checks grant permission or one of them denies it
    if( perm ) {
      if( _.isBoolean(perm.allow) ) {
        return proceed(perm.allow,'allow',null,args,prior,done)
      }
      else if( perm.act ) {
        var allow = !!perm.act.find(args)
        return proceed(allow,'act',null,args,prior,done)
      }
      else if(perm.roles) {

        var action = getAction(args)

        var entityDef = {
          zone: args.zone,
          base: args.base,
          name: args.name
        }

        // TODO: findall instead
        var aclAuthProcedure = entitiesACLs.find(entityDef)

        if(aclAuthProcedure) {

          var context = {
            user: user
          }

          if(action === 'r') { // for list and load action, filter/authorize after calling the 'prior' function to check obj attributes
            prior(args, function(err, result) {
              if(err) {
                done(err, undefined)
              }
              else {
                filterAccess(seneca, aclAuthProcedure, result, action, perm.roles, context, done)
              }
            })

          }
          else if(action === 'u'){
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
                aclAuthProcedure.authorize(result, action, perm.roles, context, function(err, authDecision) {

                  if(authDecision && authDecision.authorize && authDecision.inherit && authDecision.inherit.length > 0) {
                    var inherit = authDecision.inherit[0]
                    checkACLsWithDBEntity(seneca, inherit.entity, inherit.id, action, perm.roles, context, function(err, inheritedAuthDecision) {

                      var authorized = !err && inheritedAuthDecision.authorize
                      seneca.log.info('authorization', authorized ? 'granted' : 'denied',
                                      'for action [', action, ']',
                                      'on entity [', entityDef.zone + '/' + entityDef.base + '/'+entityDef.name, ']',
                                       'acls:', authDecision.history.concat(inheritedAuthDecision.history))
                      proceed(!err && authDecision.authorize, 'acl', null, args, prior, done)
                    })

                  } else {
                    var authorized = !err && authDecision.authorize


                    seneca.log.info('authorization', authorized ? 'granted' : 'denied',
                                    'for action [', action, ']',
                                    'on entity [', entityDef.zone + '/' + entityDef.base + '/'+entityDef.name, ']',
                                     'acls:', authDecision.history)
                    proceed(!err && authDecision.authorize, 'acl', null, args, prior, done)
                  }
                })
              }
            })

          } else {

            aclAuthProcedure.authorize(args.ent, action, perm.roles, context, function(err, authDecision) {
              if(authDecision && authDecision.authorize && authDecision.inherit && authDecision.inherit.length > 0) {
                var inherit = authDecision.inherit[0]
                checkACLsWithDBEntity(seneca, inherit.entity, inherit.id, action, perm.roles, context, function(err, inheritedAuthDecision) {

                  var authorized = !err && inheritedAuthDecision.authorize
                  seneca.log.info('authorization', authorized ? 'granted' : 'denied',
                                  'for action [', action, ']',
                                  'on entity [', entityDef.zone + '/' + entityDef.base + '/'+entityDef.name, ']',
                                   'acls:', authDecision.history.concat(inheritedAuthDecision.history))
                  proceed(!err && inheritedAuthDecision.authorize, 'acl', null, args, prior, done)
                })

              } else {
                var authorized = !err && authDecision.authorize
                seneca.log.info('authorization', authorized ? 'granted' : 'denied',
                                'for action [', action, ']',
                                'on entity [', entityDef.zone + '/' + entityDef.base + '/'+entityDef.name, ']',
                                 'acls:', authDecision.history)
                proceed(!err && authDecision.authorize, 'acl', null, args, prior, done)
              }
            })
          }
        }
        else {
          return prior(args, done)
        }
      }
      else if( perm.entity ) {
        var opspec = perm.entity.find(args)

        var result = allow_ent_op(args,opspec)
        return proceed(result.allow,'entity/operation',{allowed:opspec,need:result.need},args,prior,done)
      }
      else if( perm.own ) {
        var opspec = perm.own.entity.find(args)
        var owner  = perm.own.owner
        var result = allow_ent_op(args,opspec)

        if( !result.allow ) return seneca.fail({code:'perm/fail/own',allowed:opspec,need:result.need,args:args,status:denied},done);

        if( 'save' == args.cmd || 'load' == args.cmd || 'remove' == args.cmd ) {
          var ent = args.ent
          var id = 'load'==args.cmd ? (args.q && args.q.id) : ent.id


          // automatically set owner field
          if( 'save' == args.cmd ) {
            ent.owner = owner
          }

          if( id ) {
            var checkent = globalSeneca.make(ent.canon$({object$:true}))
            checkent.load$(id,function(err,existing){
              if( err ) return done(err);


              if( existing && existing.owner !== owner ) {
                return globalSeneca.fail({code:'perm/fail/own',owner:owner,args:args,status:denied},done);
              }

              return prior(args,done)
            })
          }
          else {
            // load with query
            if( args.q ) {
              args.q.owner = owner
            }
            ent.owner = owner
            return prior(args,done)
          }
        }
        else {
          args.q.owner = owner
          return prior(args,done)
        }
      }
      else return seneca.fail({code:'perm/no-match',args:args},done)
    }

    // need an explicit perm$ arg to trigger a permcheck
    // this allows internal operations to proceed as normal
    else {

      return prior(args,done)
    }
  }



  globalSeneca.add({init:name}, function(args,done){


    if( _.isBoolean(options.act) && options.act ) {
      _.each( globalSeneca.list(), function( act ){
        globalSeneca.add(act,permcheck)
      })
    }
    else if( _.isArray( options.act ) ) {
      _.each(options.act,function( pin ){
        globalSeneca.add(pin,permcheck)
      })
    }


    var cmds = ['save','load','list','remove']

    options.entity = _.isBoolean(options.entity) ? (options.entity ? ['-/-/-'] : []) : (options.entity || [])

    buildACLs()

    _.each(options.entity,function( entspec ){
      _.each(cmds,function(cmd){
        entspec = _.isString(entspec) ? globalSeneca.util.parsecanon(entspec) : entspec
        var spec = _.extend({role:'entity',cmd:cmd},entspec)
        globalSeneca.add(spec,permcheck)
      })
    })


    options.own = _.isBoolean(options.own) ? (options.own ? ['-/-/-'] : []) : (options.own || [])

    _.each(options.own,function( entspec ){
      _.each(cmds,function(cmd){
        entspec = _.isString(entspec) ? globalSeneca.util.parsecanon(entspec) : entspec
        var spec = _.extend({role:'entity',cmd:cmd},entspec)
        globalSeneca.add(spec,permcheck)
      })
    })


    done()
  })



  function makeperm(permspec) {
    if( permspec.ready ) {
      return permspec
    }

    var perm = {
      ready:true,
      toString: function() {
        return 'perm: '+
          'allow: '+this.allow+', '+
          'act: '+(this.act?this.act.toString():'')+', '+
          'entity: '+(this.entity?this.entity.toString():'')+', '+
          'own: '+(this.own?this.own.entity.toString()+' (owner:'+this.own.owner+')':'')
      }
    }

    if( permspec.allow ) {
      perm.allow = !!permspec.allow
    }


    function make_router(permspec,name) {
      var router = globalSeneca.util.router()

      var pinspec = permspec[name]
      if( _.isArray(pinspec) ) {
        _.each(pinspec,function(entry){
          if( _.isUndefined(entry.perm$) ) {
            throw globalSeneca.fail({code:'perm/no-perm-defined',entry:entry})
          }

          var opspec = entry.perm$
          var typespec = globalSeneca.util.clean(_.clone(entry))
          router.add(typespec,opspec)
        })
      }
      else if( _.isObject(pinspec) && ('entity'==name || 'own'==name) ) {
        _.each(pinspec,function(perm$,canonstr){
          router.add( globalSeneca.util.parsecanon(canonstr), perm$ )
        })
      }

      perm[name] = router
    }

    if( permspec.act ) {
      make_router(permspec,'act')
    }
    if( permspec.entity ) {
      make_router(permspec,'entity')
    }
    if( permspec.roles ) {
      perm.roles = permspec.roles
    }
    if( permspec.own ) {
      make_router(permspec,'own')
      var entity = perm.own
      perm.own = {
        entity:entity,
        owner:permspec.owner
      }
    }

    return perm
  }


  var nilperm = makeperm({})
  var anonperm = makeperm(options.anon)



  globalSeneca.add({role:name,cmd:'makeperm'}, function(args,done){
    var perm = makeperm( args.perm )
    done(null,perm)
  })


  function service(req,res,next) {
    if( req.seneca.user ) {
      var user = req.seneca.user
      if( user.admin ) {
        // don't make perm checks
        return next();
      }
      else {
        var perm = nilperm
        if( user.perm ) {
          perm = makeperm(user.perm)
        }
        else {
          user.perm = {}
        }
        user.perm.owner = user.id
        res.seneca = req.seneca = req.seneca.delegate({perm$:perm, user$: user})
        req.seneca.user = user

        return next()
      }
    }
    else {
      res.seneca = req.seneca = req.seneca.delegate({perm$:anonperm})
      return next()
    }
  }


  globalSeneca.act({role:'web',use:service})


  return {
    name:name,
    exports:{
      make:makeperm
    }
  }
}

