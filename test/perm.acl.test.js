/* Copyright (c) 2013-2014 Richard Rodger */
"use strict";


// mocha perm.test.js


var seneca  = require('seneca')

var assert  = require('chai').assert

var gex     = require('gex')
var async   = require('async')


describe('perm acl', function() {

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
      name: 'read access to foobar EMEA entities',
      roles: ['EMEA_READ'],
      entities: [{
        zone: undefined,
        base: undefined,
        name: 'foobar'
      }],
      control: 'sufficient',
      actions: 'r',
      conditions: [{
          attributes: {
            'region': 'EMEA'
          }
        }
      ]
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
    },{
      name: 'item: inherit foobar reference',
      roles: [],
      entities: [{
        zone: undefined,
        base: undefined,
        name: 'item'
      }],
      control: 'required',
      actions: 'r',
      conditions: [
        '{foobar::foobar}',
        {
          attributes: {
            'type': 'inherit'
          }
        }
      ]
    },{
      name: 'owner only for todos',
      roles: ['my_todos'],
      entities: [{
        zone: undefined,
        base: undefined,
        name: 'todo'
      }],
      control: 'required',
      actions: 'crud',
      conditions: [{
          attributes: {
            'owner': '{user.id}'
          }
        }
      ]
    }]
  })

  it('seneca ready', function(done) {
    si.ready(done)
  })

//   it('entity level access', function(done) {

//     var psi = si.delegate({perm$:{roles:['foobar']}})

//     var pf1 = psi.make('foobar')

//     ;pf1.save$(function(err,pf1){
//       assert.isNull(err)
//       assert.isNotNull(pf1.id)

//     ;pf1.load$(pf1.id,function(err,pf1){
//       assert.isNull(err)
//       assert.isNotNull(pf1.id)

//       pf1.a=2

//     ;pf1.save$(function(err,pf1){
//       assert.isNull(err)

//       done()

//     }) }) })

//   })

//   it('attributes based access', function(done) {

//     var psi = si.delegate({perm$:{roles:['foobar', 'EMEA']}})

//     var pf1 = psi.make('foobar',{region:'EMEA'})

//     ;pf1.save$(function(err,pf1){
//       assert.isNull(err)
//       assert.isNotNull(pf1.id)

//     ;pf1.load$(pf1.id,function(err,pf1){
//       assert.isNull(err)
//       assert.isNotNull(pf1.id)

//       pf1.a=2

//     ;pf1.save$(function(err,pf1){
//       assert.isNull(err)

//       done()

//     }) }) })

//   })


//   it('attribute based rejection', function(done) {

//     var psi = si.delegate({perm$:{roles:['foobar']}})

//     var pf1 = psi.make('foobar',{region:'EMEA'})

//     ;pf1.save$(function(err,pf1){
//       assert.isNotNull(err)
//       assert.isNotNull(err.seneca)
//       assert.equal(err.seneca.code, 'perm/fail/acl')

//       done()
//     })

//   })


//   it('entity level rejection', function(done) {

//     var psi = si.delegate({perm$:{roles:['EMEA']}})

//     var pf1 = psi.make('foobar',{region:'EMEA'})

//     ;pf1.save$(function(err,pf1){
//       assert.isNotNull(err)
//       assert.isNotNull(err.seneca)
//       assert.equal(err.seneca.code, 'perm/fail/acl')

//       done()
//     })
//   })


//   it('list filtering', function(done) {

//     var psi = si.delegate({perm$:{roles:[]}})
//     var psiPriv = si.delegate({perm$:{roles:['private_items']}})

//     var pf1 = psi.make('item',{number: 1, status: 'public'})
//     var pf2 = psiPriv.make('item',{number: 2, status: 'private'})
//     var pf3 = psiPriv.make('item',{number: 3, status: 'private'})

//     ;pf1.save$(function(err,pf1){
//       assert.isNull(err)
//       assert.isNotNull(pf1.id)

//     ;pf2.save$(function(err,pf2){
//       assert.isNull(err)
//       assert.isNotNull(pf2.id)

//     ;pf3.save$(function(err,pf3){
//       assert.isNull(err)
//       assert.isNotNull(pf3.id)

//     ;pf1.list$(function(err, publicList) {

//       assert.isNull(err)
//       assert.isNotNull(publicList)
//       assert.equal(publicList.length, 1)

//     })


//     ;pf2.list$(function(err, privateList) {

//       assert.isNull( err )
//       assert.isNotNull(privateList)
//       assert.equal(privateList.length, 3)

//       done()
//     }) }) }) })
//   })

//   it('context based access', function(done) {

//     var user = {
//       id: 'test_user_'+Date.now()
//     }

//     var psi = si.delegate({user$: user, perm$:{roles:['my_todos']}})

//     var pf1 = psi.make('todo',{owner: user.id})
//     var pf2 = psi.make('todo',{owner: 'does not exist'})

//     ;pf1.save$(function(err,pf1){
//       assert.isNull(err)
//       assert.isNotNull(pf1.id)

//     ;pf1.load$(pf1.id,function(err,pf1){
//       assert.isNull(err)
//       assert.isNotNull(pf1.id)

//       pf1.a=2

//     ;pf1.save$(function(err,pf1){
//       assert.isNull(err)


//     ;pf2.save$(function(err, pf2) {
//       assert.isNotNull(err)

//       done()

//     }) }) }) })

//   })


//   it('updating an object runs the ACLs against existing values', function(done) {

//     var emeaSeneca = si.delegate({perm$:{roles:['foobar', 'EMEA']}})
//     var foobarSeneca = si.delegate({perm$:{roles:['foobar', 'EMEA_READ']}})
//     var foobar2Seneca = si.delegate({perm$:{roles:['foobar']}})

//     var pf1 = emeaSeneca.make('foobar',{region:'EMEA'})

//     ;pf1.save$(function(err, pf1) {
//       assert.isNull(err)
//       assert.isNotNull(pf1.id)

//       var pf11 = foobarSeneca.make('foobar',{id: pf1.id, region: 'APAC'})

//     ;pf11.save$(function(err, pf11) {
//       assert.isNotNull(err)
//       assert.isNotNull(err.seneca)
//       assert.equal(err.seneca.code, 'perm/fail/acl')

//       var pf12 = foobar2Seneca.make('foobar',{id: pf1.id, region: 'APAC'})

//     ;pf12.save$(function(err, pf11) {
//       assert.isNotNull(err)
//       assert.isNotNull(err.seneca)
//       assert.equal(err.seneca.code, 'perm/fail/acl')

//       done()
//     }) }) })
//   })


  it('inherit ACLs', function(done) {

    var emeaSeneca = si.delegate({perm$:{roles:['foobar', 'EMEA']}})
    var apacSeneca = si.delegate({perm$:{roles:['foobar']}})

    var emeaFoobar = emeaSeneca.make('foobar',{region: 'EMEA'})

    ;emeaFoobar.save$(function(err, emeaFoobar) {
      assert.isNull(err)
      assert.isNotNull(emeaFoobar.id)

      var item = emeaSeneca.make('item',{foobar: emeaFoobar.id, type: 'inherit'})

    ;item.save$(function(err, item) {
      assert.isNull(err)
      assert.isNotNull(item.id)

    console.log('\n\ninheritance check 1', JSON.stringify(item))
    ;item.load$(item.id,function(err,item){
      assert.isNull(err)
      assert.isNotNull(item.id)

      var deniedItem = apacSeneca.make('item')

    console.log('\n\ninheritance check 2', JSON.stringify(deniedItem))
    ;deniedItem.load$(item.id, function(err,deniedItem){
      assert.isNotNull(err)
      assert.isNotNull(err.seneca)
      assert.equal(err.seneca.code, 'perm/fail/acl')

      done()
    }) }) }) })
  })
})
