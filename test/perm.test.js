/* Copyright (c) 2013-2014 Richard Rodger */
"use strict";

var seneca  = require('seneca')

var Lab = require('lab')
var Code = require('code')

var lab = exports.lab = Lab.script()
var describe = lab.describe
var it = lab.it
var expect = Code.expect

var gex     = require('gex')
var async   = require('async')

var testopts = { log: 'silent' }


describe('perm', function() {

  it('allow', function(done){
    var si = seneca(testopts)

    si.add({a:1,b:2},function(args,done){done(null,''+args.a+args.b+args.c)})


    si.use( '..', {act:[
      {a:1,b:2},
      {a:1,b:2,d:4}
    ]})


    si.ready(function(){

      si.act('a:1,b:2,c:3', function (err, out) {
        expect(err).to.not.exist()
        expect(out).to.equal('123')

        si.act('a:1,b:2,c:3', {perm$: {allow: true}}, function (err, out) {
          expect(err).to.not.exist()
          expect(out).to.equal('123')

          si.act('a:1,b:2,c:3', {perm$: {allow: false}}, function (err, out) {
            expect(err).to.exist()
            expect(err.seneca.code).to.equal('perm/fail/allow')

            si.act('a:1,b:2,c:3,d:4', function (err, out) {
              expect(err).to.not.exist()
              expect(out).to.equal('123')

              si.act('a:1,b:2,c:3,d:4', {perm$: {allow: true}}, function (err, out) {
                expect(err).to.not.exist()
                expect(out).to.equal('123')

                si.act('a:1,b:2,c:3,d:4', {perm$: {allow: false}}, function (err, out) {
                  expect(err).to.exist()
                  expect(err.seneca.code).to.equal('perm/fail/allow')

                  var act = si.util.router()
                  act.add({a: 1, b: 2}, true)

                  si.act('a:1,b:2,c:3', {perm$: {act: act}}, function (err, out) {
                    expect(err).to.not.exist()
                    expect(out).to.equal('123')

                    done();

                  }) }) }) }) }) })
      })

    })
  })


  it('entity', function(done) {
    var si = seneca(testopts)

    si.use( '..', {
      entity:[
        {name:'foo'},
        'bar'
      ]
    })


    si.ready(function(testopts){

      var entity = si.util.router()
      entity.add({name:'foo'},'cr')
      entity.add({name:'bar'},'rq')

      var b1 = si.make('bar',{b:2}).save$()

      var psi = si.delegate({perm$:{entity:entity}})
      var pf1 = psi.make('foo',{a:1})
      var pb1 = psi.make('bar')

      pf1.save$(function (err, pf1) {
        expect(err).to.not.exist()
        expect(pf1.id).to.exist()
        expect(pf1.a).to.equal(1)

        pf1.load$(pf1.id, function (err, pf1) {
          expect(err).to.not.exist()
          expect(pf1.id).to.exist()
          expect(pf1.a).to.equal(1)

          pf1.a = 2
          pf1.save$(function (err, pf1) {
            expect(err).to.exist()
            expect(err.seneca.valmap.allowed).to.equal('cr')
            expect(err.seneca.valmap.need).to.equal('u')


            pb1.list$({b: 2}, function (err, list) {
              expect(err).to.not.exist()
              expect(list[0].b).to.equal(2)

              done();

      }) }) }) })

    })

  })

  // TODO: test all ent cmds



  it('entity-boolean', function(done){
    var si = seneca(testopts)

    si.use( '..', {
      // apply perm check to all entities
      entity:true
    })


    si.ready(function(){

      var entity = si.util.router()
      entity.add({name:'bar'},'rq')

      var f1 = si.make('foo',{a:1}).save$()
      var b1 = si.make('bar',{b:2}).save$()

      var psi = si.delegate({perm$:{entity:entity}})

      var pf1 = psi.make('foo')
      var pb1 = psi.make('bar')

      pf1.list$({a: 1}, function (err, list) {
        expect(err).to.exist()
        expect(err.seneca.valmap.allowed).to.equal(null)
        expect(err.seneca.valmap.need).to.equal('q')

        pb1.list$({b: 2}, function (err, list) {
          expect(err).to.not.exist()
          expect(list[0].b).to.equal(2)

          done();

      }) })

    })
  })


  it('owner', function(done){
    var si = seneca(testopts)

    si.use( '..', {
      own:[
        {name:'foo'}
      ]
    })


    si.ready(function(){

      var entity = si.util.router()
      entity.add({name:'foo'},'crudq')

      var os1 = si.delegate({perm$:{own:{entity:entity,owner:'o1'}}})
      var f1 = os1.make('foo')
      f1.a=1
      f1.save$(function(err,f1){
        expect(err).to.not.exist()
        expect(f1.a).to.equal(1)
        expect(f1.owner).to.equal('o1')

        f1.load$(f1.id,function(err,f1){
          expect(err).to.not.exist()
          expect(f1.id).to.exist()
          expect(f1.a).to.equal(1)
          expect(f1.owner).to.equal('o1')

          var os2 = si.delegate({perm$:{own:{entity:entity,owner:'o2'}}})
          var f2 = os2.make('foo')

          f2.load$(f1.id,function(err,f2o){
            expect(err).to.exist()
            expect(err.seneca.code).to.equal('perm/fail/own')
            expect(err.seneca.valmap.owner).to.equal('o2')
            //console.log(err)

            done();
          })
        })
      })
    })
  })


  it('makeperm',function(done){
    var si = seneca(testopts)

    si.use( '..', {
      act:[
        {a:1},
        {b:2},
      ]
    })
    
    si.add({a:1},function(args,done){done(null,''+args.a+args.c)})
    si.add({b:2},function(args,done){done(null,''+args.b+args.c)})


    si.ready(function(){

      si.act('role:perm,cmd:makeperm',
          { perm: { act: [{a: 1,perm$: true}] } }, function(err,perm){
        
        expect(err).to.not.exist()

        si.act('a:1,c:3',{perm$:perm},function(err,out){
          expect(err).to.not.exist()
          expect(out).to.equal('13')
          
          si.act('b:2,c:3',{perm$:perm},function(err,out){
            expect(err).to.exist()
            expect(err.seneca.code).to.equal('perm/fail/act')

            done()
          })
        })
      })
    })
  })

})
