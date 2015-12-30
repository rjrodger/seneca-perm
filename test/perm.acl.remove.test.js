/* Copyright (c) 2013-2014 Richard Rodger */
'use strict'

var seneca = require('seneca')

var Lab = require('lab')
var Code = require('code')

var lab = exports.lab = Lab.script()
var describe = lab.describe
var it = lab.it
var expect = Code.expect

var testopts = {log: 'silent'}


describe('perm acl', function () {
  describe('remove', function () {
    var si = seneca(testopts)

    si.use('../perm.js', {
      accessControls: [{
        name: 'can delete foobar',
        roles: ['foobar'],
        entities: [{
          zone: undefined,
          base: undefined,
          name: 'foobar'
        }],
        control: 'required',
        actions: ['remove'],
        conditions: []
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

    it('remove granted', function (done) {
      var psi = si.delegate({perm$: {roles: ['foobar']}})

      var pf1 = psi.make('foobar', {region: 'EMEA'})

      pf1.save$(function (err, pf1) {
        expect(err).to.not.exist()
        expect(pf1.id).to.exist()
        expect(pf1.region).to.equal('EMEA')

        pf1.load$(pf1.id, function (err, pf1) {
          expect(err).to.not.exist()
          expect(pf1.id).to.exist()
          expect(pf1.region).to.equal('EMEA')

          pf1.remove$({id: pf1.id}, function (err, pf1) {
            expect(err).to.not.exist()
            expect(pf1.id).to.exist()
            expect(pf1.region).to.equal('EMEA')
            done()
          })
        })
      })
    })

    it('remove denied', function (done) {
      var psi = si.delegate({perm$: {roles: ['foobar']}})
      var psiNoRemove = si.delegate({perm$: {roles: []}})

      var pf1 = psi.make('foobar', {region: 'EMEA'})
      var pf1NoRemove = psiNoRemove.make('foobar')

      pf1.save$(function (err, pf1) {
        expect(err).to.not.exist()
        expect(pf1.id).to.exist()
        expect(pf1.region).to.equal('EMEA')

        pf1.load$(pf1.id, function (err, pf1) {
          expect(err).to.not.exist()
          expect(pf1.id).to.exist()
          expect(pf1.region).to.equal('EMEA')

          pf1NoRemove.remove$({id: pf1.id}, function (err, pf1) {
            expect(err).to.exist() // 'expected access denied error')
            done()
          })
        })
      })
    })
  })
})