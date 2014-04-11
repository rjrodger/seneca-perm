/* Copyright (c) 2013-2014 Richard Rodger, MIT License */
"use strict";


var util = require('util')
var patrun = require('patrun')

var _ = require('underscore')

var AccessControlProcedure = require('./lib/AccessControlProcedure.js')

var name = "perm"


// TODO: should be able to dynamically add perms so they can be used from custom plugins


module.exports = function(options) {
  var seneca = this

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
    if( !allow ) return seneca.fail(_.extend({},meta||{},{code:'perm/fail/'+type,args:args,status:denied}),done);
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

  // TODO: move this func out of this file
  function filterAccess(aclAuthProcedure, entityOrList, action, roles, callback) {
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
          expectedCallbackCount --

          seneca.log.info('authorization', authDecision.authorize ? 'granted' : 'denied',
                          'for action [', action, ']',
                          'on entity [',  entity.id, ']',
                           'acls:', authDecision.history)

          if(authDecision.authorize) {
            filteredList.push(entity)
          }
          if(expectedCallbackCount === 0) {
            callback(undefined, filteredList)
          }
        }
      }
    }

    if(_.isArray(entityOrList)) {
      expectedCallbackCount = entityOrList.length
      for(var i = 0 ; i < entityOrList.length ; i++) {
        aclAuthProcedure.authorize(entityOrList[i], action, roles, createEntityAccessHandler(entityOrList[i]))
      }
    } else {
      expectedCallbackCount = 1
      aclAuthProcedure.authorize(entityOrList, action, roles, function(err, authDecision) {
        if(err || !authDecision.authorize) {
          // TODO: proper 401 propagation
          callback(err || new Error('unauthorized'), undefined)
        } else {
          callback(undefined, entityOrList)
        }
      })
    }
  }


  function permcheck(args,done) {

    var prior = this.prior
    if( !prior ) {
      return seneca.fail({code:'perm/no-prior',args:args},done)
    }

    var perm = args.perm$

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

          if(action === 'r') { // for list and load action, filter/authorize after calling the 'prior' function to check obj attributes
            prior(args, function(err, result) {
              if(err) {
                done(err, undefined)
              }
              else {
                filterAccess(aclAuthProcedure, result, action, perm.roles, done)
              }
            })

          }
          else {

            aclAuthProcedure.authorize(args.ent, action, perm.roles, function(err, result) {
              var authorized = !err && result.authorize
              seneca.log.info('authorization', authorized ? 'granted' : 'denied',
                              'for action [', action, ']',
                              'on entity [', entityDef.zone + '/' + entityDef.base + '/'+entityDef.name, ']',
                               'acls:', result.history)
              proceed(!err && result.authorize, 'acl', null, args, prior, done)
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
            var checkent = seneca.make(ent.canon$({object$:true}))
            checkent.load$(id,function(err,existing){
              if( err ) return done(err);


              if( existing && existing.owner !== owner ) {
                return seneca.fail({code:'perm/fail/own',owner:owner,args:args,status:denied},done);
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



  seneca.add({init:name}, function(args,done){


    if( _.isBoolean(options.act) && options.act ) {
      _.each( seneca.list(), function( act ){
        seneca.add(act,permcheck)
      })
    }
    else if( _.isArray( options.act ) ) {
      _.each(options.act,function( pin ){
        seneca.add(pin,permcheck)
      })
    }


    var cmds = ['save','load','list','remove']

    options.entity = _.isBoolean(options.entity) ? (options.entity ? ['-/-/-'] : []) : (options.entity || [])

    buildACLs()

    _.each(options.entity,function( entspec ){
      _.each(cmds,function(cmd){
        entspec = _.isString(entspec) ? seneca.util.parsecanon(entspec) : entspec
        var spec = _.extend({role:'entity',cmd:cmd},entspec)
        seneca.add(spec,permcheck)
      })
    })


    options.own = _.isBoolean(options.own) ? (options.own ? ['-/-/-'] : []) : (options.own || [])

    _.each(options.own,function( entspec ){
      _.each(cmds,function(cmd){
        entspec = _.isString(entspec) ? seneca.util.parsecanon(entspec) : entspec
        var spec = _.extend({role:'entity',cmd:cmd},entspec)
        seneca.add(spec,permcheck)
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
      var router = seneca.util.router()

      var pinspec = permspec[name]
      if( _.isArray(pinspec) ) {
        _.each(pinspec,function(entry){
          if( _.isUndefined(entry.perm$) ) {
            throw seneca.fail({code:'perm/no-perm-defined',entry:entry})
          }

          var opspec = entry.perm$
          var typespec = seneca.util.clean(_.clone(entry))
          router.add(typespec,opspec)
        })
      }
      else if( _.isObject(pinspec) && ('entity'==name || 'own'==name) ) {
        _.each(pinspec,function(perm$,canonstr){
          router.add( seneca.util.parsecanon(canonstr), perm$ )
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
//       var router = seneca.util.router()
//       router.add( seneca.util.parsecanon('-/-/-'), 'crudq' )
//       perm.roles = router
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



  seneca.add({role:name,cmd:'makeperm'}, function(args,done){
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
        res.seneca = req.seneca = req.seneca.delegate({perm$:perm})
        req.seneca.user = user

        return next()
      }
    }
    else {
      res.seneca = req.seneca = req.seneca.delegate({perm$:anonperm})
      return next()
    }
  }


  seneca.act({role:'web',use:service})


  return {
    name:name,
    exports:{
      make:makeperm
    }
  }
}

