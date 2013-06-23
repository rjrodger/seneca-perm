/* Copyright (c) 2013 Richard Rodger, MIT License */
"use strict";


var util = require('util')


var _ = require('underscore')


var name = "perm"





module.exports = function(options) {
  var seneca = this

  options = this.util.deepextend({
    status: {
      denied: 401
    }
  },options)


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
    
    var allow = false
    _.each(ops.split(''),function(op){
      allow = ~opspec.indexOf(op) || allow
    })

    return {allow:!!allow,ops:ops}
  }


  function permcheck(args,done) {
    var parent = this.parent
    if( !parent ) {
      return seneca.fail({code:'perm/no-parent',args:args},done)
    }

    var perm = args.perm$

    //console.log(''+perm)

    if( perm ) {
      if( _.isBoolean(perm.allow) ) {
        proceed(perm.allow,'allow',null,args,parent,done)
      }
      else if( perm.act ) {
        var allow = !!perm.act.find(args)
        proceed(allow,'act',null,args,parent,done)
      }
      else if( perm.entity ) {
        var opspec = perm.entity.find(args)

        var result = allow_ent_op(args,opspec)
        //console.log('PERM.ENTITY '+opspec+' result:'+util.inspect(result)+' args.cmd='+args.cmd )
        //console.log(perm.entity.toString())

        proceed(result.allow,'entity/operation',{allowed:opspec,was:result.ops},args,parent,done)
      }
      else if( perm.own ) {
        var opspec = perm.own.entity.find(args)
        var owner  = perm.own.owner
        var result = allow_ent_op(args,opspec)
        
        //console.log('opspec:'+opspec+' owner:'+owner+' result:'+util.inspect(result)+' args.cmd='+args.cmd)

        if( !result.allow ) return seneca.fail({code:'perm/fail/own',allowed:opspec,was:result.ops,args:args,status:denied},done);
        
        if( 'save' == args.cmd || 'load' == args.cmd || 'remove' == args.cmd ) {
          var ent = args.ent
          var id = 'load'==args.cmd ? (args.q && args.q.id) : ent.id
          if( id ) {
            var checkent = seneca.make(ent.canon$({object$:true}))
            checkent.load$(id,function(err,existing){
              if( err ) return done(err);
              //console.log('OWNER='+owner+' EXISTING:'+existing.owner)

              if( existing && existing.owner !== owner ) {
                return seneca.fail({code:'perm/fail/own',owner:owner,args:args,status:denied},done);
              }

              return parent(args,done)
            })
          }
          else {
            // load with query
            if( args.q ) {
              args.q.owner = owner
            }
            ent.owner = owner
            return parent(args,done)
          }
        }
        else {
          args.q.owner = owner
          return parent(args,done)
        }
      }
      else return parent(args,done);
    }
    else return parent(args,done);
  }



  seneca.add({init:name}, function(args,done){

    _.each(options.act,function( pin ){
      seneca.add(pin,permcheck)
    })


    var cmds = ['save','load','list','remove']

    _.each(options.entity,function( entspec ){
      _.each(cmds,function(cmd){
        entspec = _.isString(entspec) ? seneca.util.parsecanon(entspec) : entspec
        var spec = _.extend({role:'entity',cmd:cmd},entspec)
        seneca.add(spec,permcheck)    
      })
    })

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
        return 'perm:'+
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

      perm[name] = router
    }

    if( permspec.act ) {
      make_router(permspec,'act')
    }
    if( permspec.entity ) {
      make_router(permspec,'entity')
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
      res.seneca = req.seneca = req.seneca.delegate({perm$:nilperm})
      return next()
    }
  }


  return {
    name:name,
    service:service
  }
}

