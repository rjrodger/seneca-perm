/* Copyright (c) 2013-2014 Richard Rodger */
'use strict'

var Seneca = require('seneca')

var Lab = require('lab')
var Code = require('code')

var lab = exports.lab = Lab.script()
var describe = lab.describe
var it = lab.it
var expect = Code.expect

var testopts = {log: 'silent'}


describe('perm acl', function () {
  describe('filter', function () {
    var si = Seneca(testopts)

    si.use(require('../perm.js'), {
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
        fields: ['id', 'name', 'number']
      }]
    })

    it('seneca ready', {timeout: 10000}, function (done) {
      si.ready(done)
    })

    it('[load] attributes based access', function (done) {
      var psi = si.delegate({perm$: {roles: ['foobar', 'region']}})
      var psiNoRegion = si.delegate({perm$: {roles: ['foobar']}})

      var pf1 = psi.make('foobar', {region: 'EMEA'})
      var pf1NoRegion = psiNoRegion.make('foobar', {region: 'EMEA'})

      pf1.save$(function (err, pf1) {
        expect(err).to.not.exist()
        expect(pf1.id, 'missing pf1.id').to.exist()
        expect(pf1.region).to.equal('EMEA')

        pf1.load$(pf1.id, function (err, pf1) {
          expect(err).to.not.exist()
          expect(pf1.id, 'missing pf1.id').to.exist()
          expect(pf1.region).to.equal('EMEA')

          pf1.a = 2

          pf1.save$(function (err, pf1) {
            expect(err).to.not.exist()
            expect(pf1.id).to.exist() // 'missing pf1.id'
            expect(pf1.region).to.equal('EMEA')

            pf1NoRegion.load$(pf1.id, function (err, pf1NoRegion) {
              expect(err).to.not.exist()
              expect(pf1NoRegion, 'missing pf1NoRegion').to.exist()
              expect(pf1NoRegion.id).to.equal(pf1.id)
              expect(pf1NoRegion.hasOwnProperty('region'), 'not to have region').to.be.false()

              done()
            })
          })
        })
      })
    })


    it('[load] attribute based rejection', function (done) {
      var psi = si.delegate({perm$: {roles: ['foobar']}})
      var psiRegion = si.delegate({perm$: {roles: ['foobar', 'region']}})

      var pf1 = psi.make('foobar', {region: 'EMEA'})
      var pf1Region = psiRegion.make('foobar', {region: 'EMEA'})

      pf1.save$(function (err, pf1) {
        expect(err).to.not.exist()
        expect(pf1).to.exist()
        expect(pf1.id).to.exist()
        expect(pf1.hasOwnProperty('region'), 'regionless user should not be able to save a region attr').to.be.false()

        pf1Region.load$(pf1.id, function (err, pf1Region) {
          expect(err).to.not.exist()
          expect(pf1).to.exist()
          expect(pf1.id).to.exist()
          expect(pf1.hasOwnProperty('region'), 'region attribute to be removed').to.be.false()

          done()
        })
      })
    })

    it('[save] attributes based rejection', function (done) {
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
            })
          })
        })
      })
    })
  })
})
