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
  describe('properties', function () {
    var si = seneca(testopts)

    si.use('../perm.js', {
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
      }, {
        name: 'hard set to false',
        roles: ['item_admin'],
        entities: [{
          zone: undefined,
          base: undefined,
          name: 'list_item'
        }],
        hard: false,
        control: 'required',
        actions: ['load', 'save_new', 'save_existing', 'list']
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

    it('seneca ready', {timeout: 10000}, function (done) {
      si.ready(done)
    })

    it('access denied - hard set to true - return permission denied', function (done) {
      var psi = si.delegate({perm$: {roles: ['email_admin']}})
      var psiList = si.delegate({perm$: {roles: ['test_role']}})

      var emailItem1 = psi.make('email', {id: 'item1', name: 'Item 1', number: 1, status: 'private'})
      var emailItem2 = psiList.make('email')

      emailItem1.save$(function (err, emailItem1) {
        expect(err).to.not.exist()
        expect(emailItem1).to.exist() // TODO check!

        emailItem2.list$(function (err, publicList) {
          expect(err).to.not.exist()
          expect(publicList).to.exist()
          expect(publicList).to.be.empty()

          done()
        })
      })
    })

    it('access denied - hard set to false - return allowed fields only', function (done) {
      var psi = si.delegate({perm$: {roles: ['item_admin']}})
      var psiList = si.delegate({
        perm$: {roles: ['test_role']},
        showSoftDenied$: true
      })

      var listItem1 = psi.make('list_item', {id: 'item1', name: 'Item 1', number: 1, status: 'private'})
      var listItem2 = psiList.make('list_item')

      listItem1.save$(function (err, listItem1) {
        expect(err).to.not.exist()
        expect(listItem1.id).to.exist()

        listItem2.list$(function (err, publicList) {
          expect(err).to.not.exist()
          expect(publicList).to.exist()
          var firstItem = publicList[0]
          expect(firstItem).to.exist()
          expect(firstItem.hasOwnProperty('name')).to.be.true()
          expect(firstItem.hasOwnProperty('number')).to.be.true()
          expect(firstItem.hasOwnProperty('id')).to.be.false()
          expect(firstItem.hasOwnProperty('status')).to.be.false()
          expect(publicList).to.have.length(1)

          done()
        })
      })
    })
  })
})