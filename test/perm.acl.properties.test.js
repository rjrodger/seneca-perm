/* Copyright (c) 2013-2014 Richard Rodger */
"use strict";


// mocha perm.test.js


var seneca  = require('seneca')

var assert  = require('chai').assert

var gex     = require('gex')
var async   = require('async')


describe('perm acl', function() {

  var si = seneca()

  si.use( '../perm.js', {
    accessControls: [{
      name: 'hard set to true',
      roles: ['email_admin'],
      entities: [{
        zone: undefined,
        base: undefined,
        name: 'email'
      }],
      hard: true,
      control: 'required',
      actions: ['load', 'save_new', 'save_existing', 'list']
    },
    {
      name: 'hard set to false',
      roles: ['item_admin'],
      entities: [{
        zone: undefined,
        base: undefined,
        name: 'list_item'
      }],
      hard: false,
      control: 'required',
      actions: ['load','save_new', 'save_existing', 'list']
    }],
    allowedProperties: [{
      entity: {
      zone: undefined,
      base: undefined,
      name: 'list_item'
      },
      fields: ['name', 'number']
    }]
  })

  it('seneca ready', function(done) {
    si.ready(done)
  })

  it('access denied - hard set to true - return permission denied', function(done) {
    var psi  = si.delegate({perm$:{roles:['email_admin']}})
    var psiList = si.delegate({perm$:{roles:['test_role']}})

    var emailItem1 = psi.make('email',{id: 'item1', name: 'Item 1', number: 1, status: 'private'})
    var emailItem2 = psiList.make('email')

    ;emailItem1.save$(function(err,emailItem1){
      assert.isNull(err, err)
      assert.isNotNull(emailItem1.id)
      
      ;emailItem2.list$(function(err, publicList) {
        assert.isNull(err, err)
        assert.isNotNull(publicList)
        assert.equal(publicList.length,0)

        done()
      }) 

    })
 
  })

  it('access denied - hard set to false - return allowed fields only', function(done) {

    var psi  = si.delegate({perm$:{roles:['item_admin']}})
    var psiList  = si.delegate({
      perm$:{roles:['test_role']},
      showSoftDenied$: true
    })

    var listItem1 = psi.make('list_item',{id: 'item1', name: 'Item 1', number: 1, status: 'private'})
    var listItem2 = psiList.make('list_item')
    
    ;listItem1.save$(function(err,listItem1){
      assert.isNull(err, err)
      assert.isNotNull(listItem1.id)
      
      ;listItem2.list$(function(err, publicList) {
        assert.isNull(err, err)
        assert.isNotNull(publicList)
        assert.equal(publicList[0].hasOwnProperty('name'), true)
        assert.equal(publicList[0].hasOwnProperty('number'), true)
        assert.equal(publicList[0].hasOwnProperty('id'), false)
        assert.equal(publicList[0].hasOwnProperty('status'), false)
        assert.equal(publicList.length, 1)

        done()
      }) 

    })
    
  })
  
})
