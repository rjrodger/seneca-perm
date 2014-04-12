/* Copyright (c) 2013-2014 Richard Rodger */
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


    si.use( '..', {act:[
      {a:1,b:2},
      {a:1,b:2,d:4}
    ]})


    si.ready(function(err){
      assert.isNull(err)

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
  })


  it('entity', function(){
    var si = seneca()

    si.use( '..', {
      entity:[
        {name:'foo'},
        'bar'
      ]
    })


    si.ready(function(err){
      assert.isNull(err)


      var entity = si.util.router()
      entity.add({name:'foo'},'cr')
      entity.add({name:'bar'},'rq')

      var b1 = si.make('bar',{b:2}).save$()

      var psi = si.delegate({perm$:{entity:entity}})
      var pf1 = psi.make('foo',{a:1})
      var pb1 = psi.make('bar')



      ;pf1.save$(function(err,pf1){
        assert.isNull(err)
        assert.isNotNull(pf1.id)
        assert.equal(1,pf1.a)

      ;pf1.load$(pf1.id,function(err,pf1){
        assert.isNull(err)
        assert.isNotNull(pf1.id)
        assert.equal(1,pf1.a)

        pf1.a=2
      ;pf1.save$(function(err,pf1){
        assert.isNotNull(err)
        assert.equal('cr',err.seneca.allowed)
        assert.equal('u',err.seneca.need)


      ;pb1.list$({b:2},function(err,list){
        assert.isNull(err)
        assert.equal(2,list[0].b)

      }) }) }) })

    })

  })

  // TODO: test all ent cmds



  it('entity-boolean', function(){
    var si = seneca()

    si.use( '..', {
      // apply perm check to all entities
      entity:true
    })


    si.ready(function(err){
      assert.isNull(err)


      var entity = si.util.router()
      entity.add({name:'bar'},'rq')

      var f1 = si.make('foo',{a:1}).save$()
      var b1 = si.make('bar',{b:2}).save$()

      var psi = si.delegate({perm$:{entity:entity}})

      var pf1 = psi.make('foo')
      var pb1 = psi.make('bar')



      ;pf1.list$({a:1},function(err,list){
        assert.isNotNull(err)
        assert.equal(null,err.seneca.allowed)
        assert.equal('q',err.seneca.need)


      ;pb1.list$({b:2},function(err,list){
        assert.isNull(err)
        assert.equal(2,list[0].b)

      }) })

    })
  })


  it('owner', function(){
    var si = seneca()

    si.use( '..', {
      own:[
        {name:'foo'}
      ]
    })


    si.ready(function(err){
      assert.isNull(err)
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


  it('makeperm',function(){

    var si = seneca()

    si.use( '..', {
      act:[
        {a:1},
        {b:2},
      ]
    })


    si.add({a:1},function(args,done){done(null,''+args.a+args.c)})
    si.add({b:2},function(args,done){done(null,''+args.b+args.c)})


    si.ready(function(err){

      si.act('role:perm,cmd:makeperm',{perm:{act:[
        {a:1,perm$:true}
      ]}}, function(err,perm){
        assert.isNull(err)

        si.act('a:1,c:3',{perm$:perm},function(err,out){
          assert.isNull(err)
          assert.equal('13',out)
        })

        si.act('b:2,c:3',{perm$:perm},function(err,out){
          assert.isNotNull(err)
          assert.equal('perm/fail/act',err.seneca.code)
        })
      })
    })
  })


  describe('acl', function(){
    var si = seneca()

    si.use( '..', {
      accessControls: [{
        name: 'access to foobar entities',
        roles: ['foobar'],
        entities: [{
          zone: undefined,
          base: undefined,
          name: 'foobar'
        }],
        control: 'required',
        actions: 'crudq',
        conditions: []
      },{
        name: 'access to foobar EMEA entities',
        roles: ['EMEA'],
        entities: [{
          zone: undefined,
          base: undefined,
          name: 'foobar'
        }],
        control: 'required',
        actions: 'crud',
        conditions: [{
            attributes: {
              'region': 'EMEA'
            }
          }
        ]
      },{
        name: 'access to foobar EMEA entities',
        roles: ['private_items'],
        entities: [{
          zone: undefined,
          base: undefined,
          name: 'item'
        }],
        control: 'required',
        actions: 'r',
        conditions: [{
            attributes: {
              'status': 'private'
            }
          }
        ]
      }]
    })

    it('seneca ready', function(done) {
      si.ready(done)
    })

    it('entity level access', function() {

      var psi = si.delegate({perm$:{roles:['foobar']}})

      var pf1 = psi.make('foobar')

      ;pf1.save$(function(err,pf1){
        assert.isNull(err)
        assert.isNotNull(pf1.id)

      ;pf1.load$(pf1.id,function(err,pf1){
        assert.isNull(err)
        assert.isNotNull(pf1.id)

        pf1.a=2

      ;pf1.save$(function(err,pf1){
        assert.isNull(err)

      }) }) })

    })

    it('attributes based access', function() {

      var psi = si.delegate({perm$:{roles:['foobar', 'EMEA']}})

      var pf1 = psi.make('foobar',{region:'EMEA'})

      ;pf1.save$(function(err,pf1){
        assert.isNull(err)
        assert.isNotNull(pf1.id)

      ;pf1.load$(pf1.id,function(err,pf1){
        assert.isNull(err)
        assert.isNotNull(pf1.id)

        pf1.a=2

      ;pf1.save$(function(err,pf1){
        assert.isNull(err)

      }) }) })

    })


    it('attribute based rejection', function() {

      var psi = si.delegate({perm$:{roles:['foobar']}})

      var pf1 = psi.make('foobar',{region:'EMEA'})

      ;pf1.save$(function(err,pf1){
        assert.isNotNull(err)
        assert.isNotNull(err.seneca)
        assert.equal(err.seneca.code, 'perm/fail/acl')
      })

    })


    it('entity level rejection', function() {

      var psi = si.delegate({perm$:{roles:['EMEA']}})

      var pf1 = psi.make('foobar',{region:'EMEA'})

      ;pf1.save$(function(err,pf1){
        assert.isNotNull(err)
        assert.isNotNull(err.seneca)
        assert.equal(err.seneca.code, 'perm/fail/acl')
      })
    })


    it('list filtering', function() {

      var psi = si.delegate({perm$:{roles:[]}})
      var psiPriv = si.delegate({perm$:{roles:['private_items']}})

      var pf1 = psi.make('item',{number: 1, status: 'public'})
      var pf2 = psiPriv.make('item',{number: 2, status: 'private'})
      var pf3 = psiPriv.make('item',{number: 3, status: 'private'})

      ;pf1.save$(function(err,pf1){
        assert.isNull(err)
        assert.isNotNull(pf1.id)

      ;pf2.save$(function(err,pf2){
        assert.isNull(err)
        assert.isNotNull(pf2.id)

      ;pf3.save$(function(err,pf3){
        assert.isNull(err)
        assert.isNotNull(pf3.id)

      ;pf1.list$(function(err, publicList) {

        assert.isNull(err)
        assert.isNotNull(publicList)
        assert.equal(publicList.length, 1)

      })


      ;pf2.list$(function(err, privateList) {

        assert.isNull(err)
        assert.isNotNull(privateList)
        assert.equal(privateList.length, 3)

      }) }) }) })
    })

  })
})
