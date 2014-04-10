
var AccessControlList = require('../lib/AccessControlList.js')

var assert = require('assert')



describe('access control list', function() {

  it('single attribute single role', function(done) {

    var obj = {region: 'EMEA'}

    var acl = new AccessControlList({
      name: 'acl1_required',
      roles: ['EMEA'],
      control: 'required',
      actions: 'rw',
      conditions: [{
          attributes: {
            'region': 'EMEA'
          }
        }
      ]
    })

    assert.ok(acl.shouldApply(obj, 'r'))
    assert.ok(acl.shouldApply(obj, 'w'))
    assert.ok(!acl.shouldApply(obj, 'd'))

    acl.authorize(obj, 'r', ['EMEA'], function(err, result) {

      assert.ok(!err, err)

      assert.ok(result)
      assert.ok(result.authorize)

      acl.authorize(obj, 'd', ['EMEA'], function(err, result) {

        assert.ok(!err, err)

        assert.ok(result)
        assert.ok(result.authorize)

        acl.authorize(obj, 'r', ['APAC'], function(err, result) {

          assert.ok(!err, err)

          assert.ok(result)
          assert.ok(!result.authorize)

          done()

        })

      })
    })


  })

  it('single action', function(done) {

    var obj = {region: 'EMEA'}

    var acl = new AccessControlList({
      name: 'acl1_required',
      roles: ['EMEA'],
      control: 'required',
      actions: 'r',
      conditions: [{
          attributes: {
            'region': 'EMEA'
          }
        }
      ]
    })

    assert.ok(acl.shouldApply(obj, 'r'))
    assert.ok(!acl.shouldApply(obj, 'w'))
    assert.ok(!acl.shouldApply(obj, 'd'))

    acl.authorize(obj, 'r', ['EMEA'], function(err, result) {

      assert.ok(!err, err)

      assert.ok(result)
      assert.ok(result.authorize)

      done()

    })


  })


})
