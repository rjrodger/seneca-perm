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


describe('perm acl', function() {

  var si = seneca(testopts)

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

    pf1.save$(function (err, pf1) {
      expect(err).to.not.exist()
      expect(pf1.id).to.exist()

      pf1.load$(pf1.id, function (err, pf1) {
        expect(err).to.not.exist()
        expect(pf1.id).to.exist()

        pf1.a = 2

        pf1.save$(function (err, pf1) {
          expect(err).to.not.exist()

          done()
    }) }) })

  })

  it('ACL save attributes based access/deny', function(done) {

    var psiNoram = si.delegate({perm$:{roles:['foobar', 'NORAM_WRITE']}})

    var pf1Noram = psiNoram.make('foobar',{region:'NORAM'})

    pf1Noram.save$(function (err, pf1Noram) {
      expect(err).to.not.exist()
      expect(pf1Noram.id).to.exist()

      pf1Noram.load$(pf1Noram.id, function (err, pf1Noram) {
        expect(err).to.not.exist()
        expect(pf1Noram.id).to.exist()

        pf1Noram.a = 2

        pf1Noram.save$(function (err, pf1Noram) {
          expect(err).to.not.exist()
          
          var psi = si.delegate({perm$: {roles: ['foobar']}})
          var pf1 = psi.make('foobar', {region: 'NORAM'})

          pf1.save$(function (err, empty) {
            expect(err).to.exist() //, 'expected a permission denied error but did not get any')
            expect(err.code).to.equal('perm/fail/acl') //'expected error code to be ACL related')

            done()
    }) }) }) })

  })

  it('attributes based access', function(done) {

    var psi = si.delegate({perm$:{roles:['foobar', 'EMEA']}})

    var pf1 = psi.make('foobar',{region:'EMEA'})

    pf1.save$(function (err, pf1) {
      expect(err).to.not.exist()
      expect(pf1.id).to.exist()

      pf1.load$(pf1.id, function (err, pf1) {
        expect(err).to.not.exist()
        expect(pf1.id).to.exist()

        pf1.a = 2

        pf1.save$(function (err, pf1) {
          expect(err).to.not.exist()

          done()
    }) }) })

  })


  it('attribute based rejection', function(done) {

    var psi = si.delegate({perm$:{roles:['foobar']}})

    var pf1 = psi.make('foobar',{region:'EMEA'})

    pf1.save$(function (err, pf1) {
      expect(err).to.exist() // 'expected a permission denied error but did not get any'
      expect(err.code).to.equal('perm/fail/acl') // 'expected error code to be ACL related'

      done()
    })

  })


  it('entity level rejection', function(done) {

    var psi = si.delegate({perm$:{roles:['EMEA']}})

    var pf1 = psi.make('foobar',{region:'EMEA'})

    pf1.save$(function (err, pf1) {
      expect(err).to.exist() // , 'expected ACL error but did not get any'
      expect(err.code).to.equal('perm/fail/acl')

      done()
    })
  })


  it('list filtering', function(done) {

    var psi = si.delegate({perm$:{roles:[]}})
    var psiPriv = si.delegate({perm$:{roles:['private_items']}})

    var pf1 = psi.make('item',{number: 1, status: 'public'})
    var pf2 = psiPriv.make('item',{number: 2, status: 'private'})
    var pf3 = psiPriv.make('item',{number: 3, status: 'private'})

    pf1.save$(function (err, pf1) {
      expect(err).to.not.exist()
      expect(pf1.id).to.exist()

      pf2.save$(function (err, pf2) {
        expect(err).to.not.exist()
        expect(pf2.id).to.exist()

        pf3.save$(function (err, pf3) {
          expect(err).to.not.exist()
          expect(pf3.id).to.exist()

          pf1.list$(function (err, publicList) {
            expect(err).to.not.exist()
            expect(publicList).to.exist()
            expect(publicList).to.have.length(1) // 'permissions should filter out forbidden objects: ' + JSON.stringify(publicList))

            pf2.list$(function (err, privateList) {

              expect(err).to.not.exist()
              expect(privateList).to.exist()
              expect(privateList).to.have.length(3)

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

    pf1.save$(function (err, pf1) {
      expect(err).to.not.exist()
      expect(pf1.id).to.exist()

      pf1.load$(pf1.id, function (err, pf1) {
        expect(err).to.not.exist()
        expect(pf1.id).to.exist()

        pf1.a = 2

        pf1.save$(function (err, pf1) {
          expect(err).to.not.exist()

          pf2.save$(function (err, pf2) {
            expect(err).to.exist()

            done()
    }) }) }) })

  })


  it('updating an object runs the ACLs against existing values', function(done) {

    var emeaSeneca = si.delegate({perm$:{roles:['foobar', 'EMEA']}})
    var foobarSeneca = si.delegate({perm$:{roles:['foobar', 'EMEA_READ']}})
    var foobar2Seneca = si.delegate({perm$:{roles:['foobar']}})

    var pf1 = emeaSeneca.make('foobar', {region:'EMEA'})

    pf1.save$(function(err, pf1) {
      expect(err).to.not.exist() // err ? err.stack : undefined)
      expect(pf1.id).to.exist() // 'creating entity should set an id on the entity'

      var pf11 = foobarSeneca.make('foobar',{id: pf1.id, region: 'APAC'})

    pf11.save$(function(err, pf11) {
      expect(err).to.exist() //  'user should be denied update capability because he can only update EMEA entities'
      expect(err.code).to.equal('perm/fail/acl') // 'expected error code to be ACL related'

      var pf12 = foobar2Seneca.make('foobar',{id: pf1.id, region: 'APAC'})

    pf12.save$(function(err, pf12) {
      expect(err).to.exist() // 'user should be denied update capability').
      expect(err.code).to.equal('perm/fail/acl') //'expected error code to be ACL related'

      done()
    }) }) })
  })


  it('inherit ACLs (read)', function(done) {

    var emeaSeneca = si.delegate({perm$:{roles:['foobar', 'EMEA']}})
    var apacSeneca = si.delegate({perm$:{roles:['foobar']}})

    var emeaFoobar = emeaSeneca.make('foobar',{region: 'EMEA'})

    emeaFoobar.save$(function (err, emeaFoobar) {
      expect(err).to.not.exist()
     expect(emeaFoobar.id).to.exist()

      var item = emeaSeneca.make('item', {foobar: emeaFoobar.id, type: 'inherit'})

      item.save$(function (err, item) {
        expect(err).to.not.exist()
        expect(item.id).to.exist()

        item.load$(item.id, function (err, item) {
          expect(err).to.not.exist()
          expect(item.id).to.exist()

          var deniedItem = apacSeneca.make('item')

          deniedItem.load$(item.id, function (err, deniedItem) {
            expect(err).to.exist() // 'expected read access to be denied by inheritance'
            expect(err.code).to.equal('perm/fail/acl')

            done()
    }) }) }) })
  })


  it('inherit ACLs (create)', function(done) {

    var emeaSeneca = si.delegate({perm$:{roles:['foobar', 'EMEA']}})
    var apacSeneca = si.delegate({perm$:{roles:['foobar', 'APAC']}})

    var emeaFoobar = emeaSeneca.make('foobar',{region: 'EMEA'})

    emeaFoobar.save$(function (err, emeaFoobar) {
      expect(err).to.not.exist()
      expect(emeaFoobar.id).to.exist()

      var item = emeaSeneca.make('item', {foobar: emeaFoobar.id, type: 'inherit'})

      item.save$(function (err, item) {
        expect(err).to.not.exist()
        expect(item.id).to.exist()

        var deniedItem = apacSeneca.make('item', {foobar: emeaFoobar.id, type: 'inherit'})

        deniedItem.save$(function (err, deniedItem) {
          expect(err).to.exist() // 'expected create capability to be denied'
          expect(err.code).to.equal('perm/fail/acl')

          done()
    }) }) })
  })


  it('inherit ACLs (update)', function(done) {

    var emeaSeneca = si.delegate({perm$:{roles:['foobar', 'EMEA']}})
    var apacSeneca = si.delegate({perm$:{roles:['foobar', 'APAC']}})

    var emeaFoobar = emeaSeneca.make('foobar',{region: 'EMEA'})

    emeaFoobar.save$(function (err, emeaFoobar) {
      expect(err).to.not.exist()
      expect(emeaFoobar.id).to.exist() // 'missing EMEA entity id'

      var item = emeaSeneca.make('item', {foobar: emeaFoobar.id, type: 'inherit'})

      item.save$(function (err, item) {
        expect(err).to.not.exist()
        expect(item.id).to.exist() // 'missing inheritance emea entity id'

        item.caramel = true

        item.save$(function (err, item) {
          expect(err).to.not.exist()
          expect(item.id).to.exist() // 'missing EMEA entity id on update'

          var deniedItem = apacSeneca.make('item', {id: item.id})

          deniedItem.save$(function (err, deniedItem) {
            expect(err).to.exist() // 'expected update capability to be denied due to inheritance'
            expect(err.code).to.equal('perm/fail/acl')

            done()
    }) }) }) })
  })

})
