/* Copyright (c) 2013-2014 Richard Rodger */
'use strict'

var seneca = require('seneca')
var Lab = require('lab')
var Code = require('code')

var lab = exports.lab = Lab.script()
var describe = lab.describe
var it = lab.it
var expect = Code.expect

var testopts = { log: 'silent' }

describe('perm acl', function () {
  describe('filter-save existing', function () {
    var si = seneca(testopts)

    si.use(require('../perm.js'), {
      accessControls: [
        {
          name: 'cannot save changes to happy attribute if it\'s already happy',
          roles: ['foobar', 'happy'],
          entities: [{
            zone: undefined,
            base: undefined,
            name: 'foobar'
          }],
          control: 'filter',
          actions: ['save_new', 'save_existing'],
          conditions: [{
            attributes: {
              happy: 1
            }
          }],
          filters: {
            happy: false
          }
        },
        {
          name: 'access to foobars',
          roles: ['foobar'],
          entities: [{
            zone: undefined,
            base: undefined,
            name: 'foobar'
          }],
          control: 'required',
          actions: ['save_new', 'save_existing', 'list', 'load', 'remove'],
          conditions: []
        }
      ],
      allowedProperties: [{
        entity: {
          zone: undefined,
          base: undefined,
          name: 'foobar'
        },
        fields: ['id', 'name', 'number', 'happy', 'tacos']
      }]
    })

    it('seneca ready', {timeout: 10000}, function (done) {
      si.ready(done)
    })

    // worked before this test.
    it('[save_new] filters should apply to conditional property.', function (done) {
      var psiNoHappy = si.delegate({perm$: {roles: ['foobar']}})

      var e = psiNoHappy.make('foobar', {a: 'a', happy: 1})

      e.save$(function (err, e) {
        expect(err).to.not.exist()
        expect(e).to.exist()
        expect(e.happy, 'unchanged to happy property').to.be.undefined()

        done()
      })
    })

    it('[save_existing] filters should apply to conditional property.', function (done) {
      var psi = si.delegate({perm$: {roles: ['foobar', 'happy']}})
      var psiNoHappy = si.delegate({perm$: {roles: ['foobar']}})

      var pf1 = psi.make('foobar', {a: 'a', happy: 1})
      var pf1NoHappy = psiNoHappy.make('foobar', {b: 'b', happy: 1})

      pf1.save$(function (err, pf1) {
        expect(err).to.not.exist()
        console.log('saved ', pf1)

        expect(pf1.id).to.exist()
        expect(pf1.happy).to.equal(1)

        pf1NoHappy.load$(pf1.id, function (err, pf1NoHappy) {
          expect(err).to.not.exist()
          expect(pf1NoHappy).to.exist()
          expect(pf1NoHappy.happy, 'unchanged to happy property').to.equal(1)

          console.log('loaded happy entity', pf1NoHappy)

          pf1NoHappy.tacos = 'yum'
          pf1NoHappy.happy = 0
          console.log('====================================++>>>>>>')
          console.log('attempting to make happy entity unhappy', pf1NoHappy)

          pf1NoHappy.save$(function (err, pf1NoHappy) {
            if (!pf1NoHappy.happy) console.log('happy entity shouldnt be unhappy!', pf1NoHappy)
            else console.log('yay still happy!')

            expect(err).to.not.exist()
            expect(pf1NoHappy).to.exist()
            expect(pf1NoHappy.happy, 'unchanged to happy property').to.equal(1)
            expect(pf1NoHappy.tacos, 'saved new tacos property').to.equal('yum')

            done()
          })
        })
      })
    })
  })
})