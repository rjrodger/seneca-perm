/* Copyright (c) 2013-2014 Richard Rodger, MIT License */
"use strict";

var util = require('util')

var _ = require('lodash')

var AccessControlProcedure = require('access-controls')

var ACLMicroservicesBuilder = require('./lib/ACLMicroservicesBuilder.js')

var name = "perm"


// TODO: should be able to dynamically add perms so they can be used from custom plugins


module.exports = function(options) {
  var globalSeneca = this

  var aclBuilder = new ACLMicroservicesBuilder(globalSeneca)

  options = this.util.deepextend({
    status: {
      denied: 401
    },
    anon:{}
  },options)

  function buildACLs() {
    if(options.accessControls) {
      var allowedProperties = buildPropertiesMap(options.allowedProperties)
      aclBuilder.register(options.accessControls, allowedProperties)
      aclBuilder.augmentSeneca(globalSeneca)
    }
  }

  function buildPropertiesMap(properties) {
    var allowedProperties = {}
    if(properties) {
      for(var i = 0; i < properties.length; i++) {
        var key = canonize(properties[i].entity)
        allowedProperties[key] = properties[i].fields
      }
    }
    return allowedProperties
  }

  function canonize(entityDef) {
    return (entityDef.zone || '-') + '/' + (entityDef.base || '-') + '/' + entityDef.name
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
    if( !allow ) return done(globalSeneca.fail(_.extend({},meta||{},{code:'perm/fail/'+type,args:args,status:denied})));
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


  function canonize(entityDef) {
    return (entityDef.zone || '-') + '/' + (entityDef.base || '-') + '/' + entityDef.name
  }


  function permcheck(args,done) {
    var seneca = this
    var prior = this.prior
    if( !prior ) {
      return done(seneca.fail({code:'perm/no-prior',args:args}))
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
        acls.executePermissions(seneca, args, prior, done)
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

        if( !result.allow ) return done(seneca.fail({code:'perm/fail/own',allowed:opspec,need:result.need,args:args,status:denied}));

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
                return done(globalSeneca.fail({code:'perm/fail/own',owner:owner,args:args,status:denied}));
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
      else return done(seneca.fail({code:'perm/no-match',args:args}))
    }

    // need an explicit perm$ arg to trigger a permcheck
    // this allows internal operations to proceed as normal
    else {

      return prior(args,done)
    }
  }

  buildACLs()

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


  return {
    name:name,
    exports:{
      make:makeperm
    }
  }
}
