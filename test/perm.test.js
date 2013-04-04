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


    si.use( '..', {pins:[
      {a:1,b:2},
      {a:1,b:2,d:4}
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


    var act = si.util.router()
    act.add( {a:1,b:2}, true )

    //console.log( act.find({a:1,b:2}) )

    si.act('a:1,b:2,c:3',{perm$:{act:act}},function(err,out){
      assert.isNull(err)
      assert.equal('123',out)
    })

    si.act('a:1,c:3',{perm$:{act:act}},function(err,out){
      assert.isNotNull(err)
    })
  })


  it('entity', function(){
    var si = seneca()

    si.use( '..', {
      entity:[
        {name:'foo'}
      ]
    })

    var entity = si.util.router()
    entity.add({name:'foo'},'cr')

    var psi = si.delegate({perm$:{entity:entity}})
    var f1 = psi.make('foo')
    f1.a=1
    f1.save$(function(err,f1){
      assert.isNull(err)
      assert.isNotNull(f1.id)
      assert.equal(1,f1.a)

      f1.load$(f1.id,function(err,f1){
        assert.isNull(err)
        assert.isNotNull(f1.id)
        assert.equal(1,f1.a)

        f1.a=2
        f1.save$(function(err,f1){
          assert.isNotNull(err)
          assert.equal('cr',err.seneca.allowed)
          assert.equal('u',err.seneca.was)
        })      
      })
    })

  })

  // TODO: test all ent cmds


  it('owner', function(){
    var si = seneca()

    si.use( '..', {
      own:[
        {name:'foo'}
      ]
    })

    //console.log(si.actroutes())

    var entity = si.util.router()
    entity.add({name:'foo'},'crudq')

    var os1 = si.delegate({perm$:{own:{entity:entity,owner:'o1'}}})
    var f1 = os1.make('foo')
    f1.a=1
    f1.save$(function(err,f1){
      assert.isNull(err)
      assert.equal(1,f1.a)
      assert.equal('o1',f1.owner)

      f1.load$(f1.id,function(err,f1){
        assert.isNull(err)
        assert.isNotNull(f1.id)
        assert.equal(1,f1.a)
        assert.equal('o1',f1.owner)

        var os2 = si.delegate({perm$:{own:{entity:entity,owner:'o2'}}})
        var f2 = os2.make('foo')

        f2.load$(f1.id,function(err,f2o){
          assert.isNotNull(err)
          assert.equal('perm/fail/own',err.seneca.code)
          assert.equal('o2',err.seneca.owner)
          //console.log(err)
        })      
      })
    })
  })

})