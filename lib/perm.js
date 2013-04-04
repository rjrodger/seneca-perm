/* Copyright (c) 2013 Richard Rodger, MIT License */
"use strict";



var _ = require('underscore')


var name = "perm"





module.exports = function(opts,register) {
  var seneca = this

  opts = this.util.deepextend({
    map:[]
  },opts)


  function perm_allow(args,done) {
    var perm = args.perm$


    if( perm ) {
      if( _.isBoolean(perm.allow) ) {
        if( !perm.allow ) return seneca.fail({code:'perm/fail/allow',args:args},done)
        return this.parent(args,done)
      }
      else return this.parent(args,done);
    }
    else return this.parent(args,done);
  }





  _.each(opts.map,function( entry ){
    var pin = entry.pin
    var perm = entry.perm
    var permfunc

    if( 'allow' == perm ) {
      permfunc = perm_allow
    }

    if( pin && permfunc ) {
      seneca.add(pin,permfunc)
    }
  })

  register(null,{name:name})
}

