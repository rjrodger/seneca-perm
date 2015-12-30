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

  si.use( require('../perm.js'), {
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
    }],
    allowedProperties: [{
      entity: {
        zone: undefined,
        base: undefined,
        name: 'item'
      },
      fields: ['id','name', 'number']
    }]
  })

  it('seneca ready', function(done) {
    this.timeout(10000)
    si.ready(done)
  })

  it('[load] attributes based access', function(done) {

    var psi = si.delegate({perm$:{roles:['foobar', 'region']}})
    var psiNoRegion = si.delegate({perm$:{roles:['foobar']}})

    var pf1 = psi.make('foobar',{region:'EMEA'})
    var pf1NoRegion = psiNoRegion.make('foobar',{region:'EMEA'})

    pf1.save$(function (err, pf1) {
      expect(err).to.not.exist()
      expect(pf1.id).to.exist() // 'missing pf1.id'
      expect(pf1.region).to.equal('EMEA')

      pf1.load$(pf1.id, function (err, pf1) {
        expect(err).to.not.exist()
        expect(pf1.id).to.exist() // 'missing pf1.id'
        expect(pf1.region).to.equal('EMEA')

        pf1.a = 2

        pf1.save$(function (err, pf1) {
          expect(err).to.not.exist()
          expect(pf1.id).to.exist() // 'missing pf1.id'
          expect(pf1.region).to.equal('EMEA')

          pf1NoRegion.load$(pf1.id, function (err, pf1NoRegion) {

            expect(err).to.not.exist()
            expect(pf1NoRegion).to.exist() // 'missing pf1NoRegion'
            expect(pf1NoRegion.id).to.equal(pf1.id)
            expect(pf1NoRegion.hasOwnProperty('region')).to.be.false() // 'object has a region attr but it should not')

            done()

    }) }) }) })

  })


  it('[load] attribute based rejection', function(done) {

    var psi = si.delegate({perm$:{roles:['foobar']}})
    var psiRegion = si.delegate({perm$:{roles:['foobar', 'region']}})

    var pf1 = psi.make('foobar',{region:'EMEA'})
    var pf1Region = psiRegion.make('foobar',{region:'EMEA'})

    pf1.save$(function(err,pf1){
      expect(err).to.not.exist()
      expect(pf1).to.exist()
      expect(pf1.id).to.exist()
      expect(pf1.hasOwnProperty('region')).to.be.false() // 'regionless user should not be able to save a region attr')

      pf1Region.load$(pf1.id, function(err, pf1Region) {
        expect(err).to.not.exist()
        expect(pf1).to.exist()
        expect(pf1.id).to.exist()
        expect(pf1.hasOwnProperty('region')).to.be.false() // 'Expected region attr to be removed')

        done()
      })
    })

  })

  it('[save] attributes based rejection', function(done) {

    var psi = si.delegate({perm$: {roles: ['foobar', 'region']}})
    var psiNoRegion = si.delegate({perm$: {roles: ['foobar']}})

    var pf1 = psi.make('foobar', {region: 'EMEA'})

    pf1.save$(function (err, pf1) {
      expect(err).to.not.exist()
      expect(pf1.id).to.exist()
      expect(pf1.region).to.equal('EMEA')

      pf1.load$(pf1.id, function (err, pf1) {
        expect(err).to.not.exist()
        expect(pf1.id).to.exist()
        expect(pf1.region).to.equal('EMEA')

        var pf1NoRegion = psiNoRegion.make('foobar', {id: pf1.id, region: 'APAC', updated: true})

        pf1NoRegion.save$(function (err, pf1NoRegion) {

          expect(err).to.not.exist()
          expect(pf1NoRegion).to.exist()
          expect(pf1NoRegion.id).to.equal(pf1.id)
          expect(pf1NoRegion.updated).to.exist()

          pf1.load$(pf1.id, function (err, loadedPf1) {
            expect(err).to.not.exist()
            expect(loadedPf1.id).to.equal(pf1.id)
            expect(loadedPf1.region).to.equal('EMEA')
            expect(loadedPf1.updated).to.exist()

            done()

    }) }) }) })
  })

})
