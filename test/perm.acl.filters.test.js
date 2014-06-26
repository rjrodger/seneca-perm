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
      name: 'access to region attribute',
      roles: ['foobar', 'region'],
      entities: [{
        zone: undefined,
        base: undefined,
        name: 'foobar'
      }],
      control: 'filter',
      actions: ['save_new', 'save_existing', 'list', 'load', 'remove'],
      conditions: [],
      filters: {
        region: false
      }
    }]
  })

  it('seneca ready', function(done) {
    si.ready(done)
  })

  it('attributes based access', function(done) {

    var psi = si.delegate({perm$:{roles:['foobar', 'region']}})
    var psiNoRegion = si.delegate({perm$:{roles:['foobar']}})

    var pf1 = psi.make('foobar',{region:'EMEA'})
    var pf1NoRegion = psiNoRegion.make('foobar',{region:'EMEA'})

    ;pf1.save$(function(err, pf1){
      assert.isNull(err)
      assert.isNotNull(pf1.id)
      assert.equal(pf1.region, 'EMEA')

    ;pf1.load$(pf1.id, function(err, pf1){
      assert.isNull(err)
      assert.isNotNull(pf1.id)
      assert.equal(pf1.region, 'EMEA')

      pf1.a=2

    ;pf1.save$(function(err, pf1){
      assert.isNull(err)
      assert.isNotNull(pf1.id)
      assert.equal(pf1.region, 'EMEA')

      pf1NoRegion.load$(pf1.id, function(err, pf1NoRegion) {

        assert.isNull(err, err)
        assert.isNotNull(pf1NoRegion)
        assert.equal(pf1NoRegion.id, pf1.id)
        assert.ok(!pf1NoRegion.hasOwnProperty('region'))

        done()
      })


    }) }) })

  })


  it('attribute based rejection', function(done) {

    var psi = si.delegate({perm$:{roles:['foobar']}})
    var psiRegion = si.delegate({perm$:{roles:['foobar', 'region']}})

    var pf1 = psi.make('foobar',{region:'EMEA'})
    var pf1Region = psiRegion.make('foobar',{region:'EMEA'})

    ;pf1.save$(function(err,pf1){
      assert.isNull(err, err)
      assert.ok(pf1)
      assert.ok(pf1.id)
      assert.ok(!pf1.hasOwnProperty('region'))

      pf1Region.load$(pf1.id, function(err, pf1Region) {
        assert.isNull(err, err)
        assert.ok(pf1)
        assert.ok(pf1.id)
        assert.ok(!pf1.hasOwnProperty('region'))

        done()
      })
    })

  })

})
