/* Copyright (c) 2013 Richard Rodger */
"use strict";


// mocha perm.test.js


var seneca  = require('seneca')

var assert  = require('chai').assert

var gex     = require('gex')
var async   = require('async')








describe('perm', function() {
  
  it('allow', function(){
    var si = seneca()

    si.add({a:1,b:2},function(args,done){done(null,''+args.a+args.b+args.c)})


    si.use( '..', {map:[
      {pin:{a:1,b:2},perm:'allow'},
      {pin:{a:1,b:2,d:4},perm:'allow'}
    ]})




    si.act('a:1,b:2,c:3',function(err,out){
      assert.isNull(err)
      assert.equal('123',out)
    })

    si.act('a:1,b:2,c:3',{perm$:{allow:true}},function(err,out){
      assert.isNull(err)
      assert.equal('123',out)
    })

    si.act('a:1,b:2,c:3',{perm$:{allow:false}},function(err,out){
      assert.isNotNull(err)
      assert.equal('perm/fail/allow',err.seneca.code)
    })


    si.act('a:1,b:2,c:3,d:4',function(err,out){
      assert.isNull(err)
      assert.equal('123',out)
    })

    si.act('a:1,b:2,c:3,d:4',{perm$:{allow:true}},function(err,out){
      assert.isNull(err)
      assert.equal('123',out)
    })

    si.act('a:1,b:2,c:3,d:4',{perm$:{allow:false}},function(err,out){
      assert.isNotNull(err)
      assert.equal('perm/fail/allow',err.seneca.code)
    })

  })

})