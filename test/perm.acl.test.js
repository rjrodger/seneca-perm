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
    accessControls: [
      {
        name: 'access to foobar entities',
        roles: ['foobar'],
        entities: [{
          zone: undefined,
          base: undefined,
          name: 'foobar'
        }],
        control: 'required',
        actions: ['save_new', 'save_existing', 'list', 'load', 'remove'],
        conditions: []
      }, {
        name: 'read access to foobar EMEA entities',
        roles: ['EMEA_READ'],
        entities: [{
          zone: undefined,
          base: undefined,
          name: 'foobar'
        }],
        control: 'sufficient',
        actions: ['list', 'load'],
        conditions: [{
            attributes: {
              'region': 'EMEA'
            }
          }
        ]
      }, {
        name: 'write access to foobar NORAM entities',
        roles: ['NORAM_WRITE'],
        entities: [{
          zone: undefined,
          base: undefined,
          name: 'foobar'
        }],
        control: 'required',
        actions: ['save_new', 'save_existing'],
        conditions: [{
            attributes: {
              'region': 'NORAM'
            }
          }
        ]
      }, {
        name: 'access to foobar EMEA entities',
        roles: ['EMEA'],
        entities: [{
          zone: undefined,
          base: undefined,
          name: 'foobar'
        }],
        control: 'required',
        actions: ['save_new', 'save_existing', 'list', 'load', 'remove'],
        conditions: [{
            attributes: {
              'region': 'EMEA'
            }
          }
        ]
      },{
        name: 'access to foobar private entities',
        roles: ['private_items'],
        entities: [{
          zone: undefined,
          base: undefined,
          name: 'item'
        }],
        hard: true,
        control: 'required',
        actions: ['list', 'load'],
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
        actions: ['save_new', 'save_existing', 'list', 'load', 'remove'],
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
        actions: ['save_new', 'save_existing', 'list', 'load', 'remove'],
        conditions: [{
            attributes: {
              'owner': '{user.id}'
            }
          }
        ]
      }
    ]
  })

  it('seneca ready', function(done) {
    si.ready(done)
  })

  it('entity level access', function(done) {

    var psi = si.delegate({perm$:{roles:['foobar']}})

    var pf1 = psi.make('foobar')

    ;pf1.save$(function(err,pf1){
      assert.isNull(err, err)
      assert.isNotNull(pf1.id)

    ;pf1.load$(pf1.id,function(err,pf1){
      assert.isNull(err, err)
      assert.isNotNull(pf1.id)

      pf1.a=2

    ;pf1.save$(function(err,pf1){
      assert.isNull(err, err)

      done()

    }) }) })

  })

  it('ACL save attributes based access/deny', function(done) {

    var psiNoram = si.delegate({perm$:{roles:['foobar', 'NORAM_WRITE']}})

    var pf1Noram = psiNoram.make('foobar',{region:'NORAM'})

    ;pf1Noram.save$(function(err, pf1Noram) {
      assert.isNull(err, err)
      assert.isNotNull(pf1Noram.id)

    ;pf1Noram.load$(pf1Noram.id,function(err, pf1Noram) {
      assert.isNull(err, err)
      assert.isNotNull(pf1Noram.id)

      pf1Noram.a=2

    ;pf1Noram.save$(function(err, pf1Noram) {
      assert.isNull(err, err)


      var psi = si.delegate({perm$:{roles:['foobar']}})
      var pf1 = psi.make('foobar',{region:'NORAM'})

    ;pf1.save$(function(err, empty) {
      assert.ok(err, 'expected a permission denied error but did not get any')
      assert.equal(err.code, 'perm/fail/acl', 'expected error code to be ACL related')

      done()
    }) }) }) })

  })

  it('attributes based access', function(done) {

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


    done()
    }) }) })

  })


  it('attribute based rejection', function(done) {

    var psi = si.delegate({perm$:{roles:['foobar']}})

    var pf1 = psi.make('foobar',{region:'EMEA'})

    ;pf1.save$(function(err, pf1) {
      assert.ok(err, 'expected a permission denied error but did not get any')
      assert.equal(err.code, 'perm/fail/acl', 'expected error code to be ACL related')

      done()
    })

  })


  it('entity level rejection', function(done) {

    var psi = si.delegate({perm$:{roles:['EMEA']}})

    var pf1 = psi.make('foobar',{region:'EMEA'})

    ;pf1.save$(function(err,pf1){
      assert.isNotNull(err, 'expected ACL error but did not get any')
      assert.equal(err.code, 'perm/fail/acl')

      done()
    })
  })


  it('list filtering', function(done) {

    var psi = si.delegate({perm$:{roles:[]}})
    var psiPriv = si.delegate({perm$:{roles:['private_items']}})

    var pf1 = psi.make('item',{number: 1, status: 'public'})
    var pf2 = psiPriv.make('item',{number: 2, status: 'private'})
    var pf3 = psiPriv.make('item',{number: 3, status: 'private'})

    ;pf1.save$(function(err,pf1){
      assert.isNull(err, err)
      assert.isNotNull(pf1.id)

    ;pf2.save$(function(err,pf2){
      assert.isNull(err, err)
      assert.isNotNull(pf2.id)

    ;pf3.save$(function(err,pf3){
      assert.isNull(err, err)
      assert.isNotNull(pf3.id)

    ;pf1.list$(function(err, publicList) {
      assert.isNull(err, err)
      assert.isNotNull(publicList)
      assert.equal(publicList.length, 1, 'permissions should filter out forbidden objects: ' + JSON.stringify(publicList))

    ;pf2.list$(function(err, privateList) {

      assert.isNull( err, err )
      assert.isNotNull(privateList)
      assert.equal(privateList.length, 3)

      done()
    }) }) }) }) })
  })

  it('context based access', function(done) {

    var user = {
      id: 'test_user_'+Date.now()
    }

    var psi = si.delegate({user$: user, perm$:{roles:['my_todos']}})

    var pf1 = psi.make('todo',{owner: user.id})
    var pf2 = psi.make('todo',{owner: 'does not exist'})

    ;pf1.save$(function(err,pf1){
      assert.isNull(err)
      assert.isNotNull(pf1.id)

    ;pf1.load$(pf1.id,function(err,pf1){
      assert.isNull(err)
      assert.isNotNull(pf1.id)

      pf1.a=2

    ;pf1.save$(function(err,pf1){
      assert.isNull(err)


    ;pf2.save$(function(err, pf2) {
      assert.isNotNull(err)

      done()

    }) }) }) })

  })


  it('updating an object runs the ACLs against existing values', function(done) {

    var emeaSeneca = si.delegate({perm$:{roles:['foobar', 'EMEA']}})
    var foobarSeneca = si.delegate({perm$:{roles:['foobar', 'EMEA_READ']}})
    var foobar2Seneca = si.delegate({perm$:{roles:['foobar']}})

    var pf1 = emeaSeneca.make('foobar', {region:'EMEA'})

    ;pf1.save$(function(err, pf1) {
      assert.isNull(err, err ? err.stack : undefined)
      assert.isNotNull(pf1.id, 'creating entity should set an id on the entity')

      var pf11 = foobarSeneca.make('foobar',{id: pf1.id, region: 'APAC'})

    ;pf11.save$(function(err, pf11) {
      assert.isNotNull(err, 'user should be denied update capability because he can only update EMEA entities')
      assert.equal(err.code, 'perm/fail/acl', 'expected error code to be ACL related')

      var pf12 = foobar2Seneca.make('foobar',{id: pf1.id, region: 'APAC'})

    ;pf12.save$(function(err, pf12) {
      assert.isNotNull(err, 'user should be denied update capability')
      assert.equal(err.code, 'perm/fail/acl', 'expected error code to be ACL related')

      done()
    }) }) })
  })


  it('inherit ACLs (read)', function(done) {

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

    ;item.load$(item.id,function(err,item){
      assert.isNull(err)
      assert.isNotNull(item.id)

      var deniedItem = apacSeneca.make('item')

    ;deniedItem.load$(item.id, function(err,deniedItem){
      assert.isNotNull(err, 'expected read access to be denied by inheritance')
      assert.equal(err.code, 'perm/fail/acl')

      done()
    }) }) }) })
  })


  it('inherit ACLs (create)', function(done) {

    var emeaSeneca = si.delegate({perm$:{roles:['foobar', 'EMEA']}})
    var apacSeneca = si.delegate({perm$:{roles:['foobar', 'APAC']}})

    var emeaFoobar = emeaSeneca.make('foobar',{region: 'EMEA'})

    ;emeaFoobar.save$(function(err, emeaFoobar) {
      assert.isNull(err, err)
      assert.isNotNull(emeaFoobar.id)

      var item = emeaSeneca.make('item',{foobar: emeaFoobar.id, type: 'inherit'})

    ;item.save$(function(err, item) {
      assert.isNull(err, err)
      assert.isNotNull(item.id)


      var deniedItem = apacSeneca.make('item',{foobar: emeaFoobar.id, type: 'inherit'})

    ;deniedItem.save$(function(err, deniedItem){
      assert.isNotNull(err, 'expected create capability to be denied')
      assert.equal(err.code, 'perm/fail/acl')

      done()
    }) }) })
  })


  it('inherit ACLs (update)', function(done) {

    var emeaSeneca = si.delegate({perm$:{roles:['foobar', 'EMEA']}})
    var apacSeneca = si.delegate({perm$:{roles:['foobar', 'APAC']}})

    var emeaFoobar = emeaSeneca.make('foobar',{region: 'EMEA'})

    ;emeaFoobar.save$(function(err, emeaFoobar) {
      assert.isNull(err, err)
      assert.isNotNull(emeaFoobar.id, 'missing EMEA entity id')

      var item = emeaSeneca.make('item',{foobar: emeaFoobar.id, type: 'inherit'})

    ;item.save$(function(err, item) {
      assert.isNull(err, err)
      assert.ok(item.id, 'missing inheritance emea entity id')

    ;item.caramel = true

    ;item.save$(function(err, item) {
      assert.isNull(err, err)
      assert.ok(item.id, 'missing EMEA entity id on update')

      var deniedItem = apacSeneca.make('item',{id: item.id})

    ;deniedItem.save$(function(err, deniedItem){
      assert.isNotNull(err, 'expected update capability to be denied due to inheritance')
      assert.equal(err.code, 'perm/fail/acl')

      done()
    }) }) }) })
  })

})
