
var AccessControlList = require('../lib/AccessControlList.js')

var assert = require('assert')



describe('access control list', function() {

  it('single attribute single role', function(done) {

    var obj = {
      nested: {
        region: 'EMEA'
      }
    }

    var acl = new AccessControlList({
      name: 'acl1_required',
      roles: ['EMEA'],
      control: 'required',
      actions: 'rw',
      conditions: [{
          attributes: {
            'nested.region': 'EMEA'
          }
        }
      ]
    })

    assert.ok(acl.shouldApply(obj, 'r').ok)
    assert.ok(acl.shouldApply(obj, 'w').ok)
    assert.ok(!acl.shouldApply(obj, 'd').ok)

    acl.authorize(obj, 'r', ['EMEA'], {}, function(err, result) {

      assert.ok(!err, err)

      assert.ok(result)
      assert.ok(result.authorize)

      acl.authorize(obj, 'd', ['EMEA'], {}, function(err, result) {

        assert.ok(!err, err)

        assert.ok(result)
        assert.ok(result.authorize)

        acl.authorize(obj, 'r', ['APAC'], {}, function(err, result) {

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

    assert.ok(acl.shouldApply(obj, 'r').ok)
    assert.ok(!acl.shouldApply(obj, 'w').ok)
    assert.ok(!acl.shouldApply(obj, 'd').ok)

    acl.authorize(obj, 'r', ['EMEA'], {}, function(err, result) {

      assert.ok(!err, err)

      assert.ok(result)
      assert.ok(result.authorize)

      done()

    })


  })

  it('should always apply on empty conditions', function(done) {

    var obj1 = {region: 'EMEA'}
    var obj2 = {region: 'APAC'}

    var acl = new AccessControlList({
      name: 'acl1_required',
      roles: ['granted'],
      control: 'required',
      actions: 'r',
      conditions: []
    })

    assert.ok(acl.shouldApply(obj1, 'r').ok)
    assert.ok(!acl.shouldApply(obj1, 'w').ok)
    assert.ok(!acl.shouldApply(obj1, 'd').ok)

    assert.ok(acl.shouldApply(obj2, 'r').ok)
    assert.ok(!acl.shouldApply(obj2, 'w').ok)
    assert.ok(!acl.shouldApply(obj2, 'd').ok)


    acl.authorize(obj1, 'r', ['granted'], {}, function(err, result) {

      assert.ok(!err, err)

      assert.ok(result)
      assert.ok(result.authorize)

      acl.authorize(obj2, 'r', ['denied'], {}, function(err, result) {

        assert.ok(!err, err)

        assert.ok(result)
        assert.ok(!result.authorize)

        done()

      })
    })


  })



  it('can apply to context', function(done) {

    var obj = {region: 'EMEA', owner: 123}

    var acl = new AccessControlList({
      name: 'acl1_required',
      roles: ['EMEA'],
      control: 'required',
      actions: 'r',
      conditions: [{
          attributes: {
            'owner': '{user.id}'
          }
        }
      ]
    })

    assert.ok(acl.shouldApply(obj, 'r').ok)
    assert.ok(!acl.shouldApply(obj, 'w').ok)
    assert.ok(!acl.shouldApply(obj, 'd').ok)

    acl.authorize(obj, 'r', ['EMEA'], {user: {id: 123}}, function(err, result) {

      assert.ok(!err, err)

      assert.ok(result)
      assert.ok(result.authorize)

      obj.owner = 1234
      acl.authorize(obj, 'r', ['EMEA'], {user: {id: 123}}, function(err, result) {

        assert.ok(!err, err)

        assert.ok(result)
        assert.ok(!result.authorize)

        done()

      })

    })


  })


  it('inheritance user::owner', function(done) {

    var obj = {region: 'EMEA', owner: 123}

    var acl = new AccessControlList({
      name: 'acl1_required',
      roles: ['EMEA'],
      control: 'required',
      actions: 'r',
      conditions: [
        '{user::owner}',
        {
          attributes: {
            'owner': '{user.id}'
          }
        }
      ]
    })

    assert.ok(acl.shouldApply(obj, 'r').ok)

    acl.authorize(obj, 'r', ['EMEA'], {user: {id: 123}}, function(err, result) {

      assert.ok(!err, err)

      assert.ok(result)
      assert.ok(result.authorize)

      assert.ok(result.inherit)
      assert.equal(result.inherit[0].id, 123)
      assert.ok(result.inherit[0].entity)
      assert.ok(!result.inherit[0].entity.zone)
      assert.ok(!result.inherit[0].entity.base)
      assert.equal(result.inherit[0].entity.name, 'user')

      obj.owner = 1234
      acl.authorize(obj, 'r', ['EMEA'], {user: {id: 123}}, function(err, result) {

        assert.ok(!err, err)

        assert.ok(result)
        assert.ok(!result.authorize)

        done()

      })

    })


  })

  it('can handle inheritance sys/user::owner', function(done) {

    var obj = {region: 'EMEA', owner: 123}

    var acl = new AccessControlList({
      name: 'acl1_required',
      roles: ['EMEA'],
      control: 'required',
      actions: 'r',
      conditions: [
        '{sys/user::owner}',
        {
          attributes: {
            'owner': '{user.id}'
          }
        }
      ]
    })

    assert.ok(acl.shouldApply(obj, 'r').ok)

    acl.authorize(obj, 'r', ['EMEA'], {user: {id: 123}}, function(err, result) {

      assert.ok(!err, err)

      assert.ok(result)
      assert.ok(result.authorize)

      assert.ok(result.inherit)
      assert.equal(result.inherit[0].id, 123)
      assert.ok(result.inherit[0].entity)
      assert.ok(!result.inherit[0].entity.zone)
      assert.equal(result.inherit[0].entity.base, 'sys')
      assert.equal(result.inherit[0].entity.name, 'user')

      obj.owner = 1234
      acl.authorize(obj, 'r', ['EMEA'], {user: {id: 123}}, function(err, result) {

        assert.ok(!err, err)

        assert.ok(result)
        assert.ok(!result.authorize)

        done()

      })

    })


  })

  it('can handle inheritance zone-1/sys/user::owner', function(done) {

    var obj = {region: 'EMEA', owner: 123}

    var acl = new AccessControlList({
      name: 'acl1_required',
      roles: ['EMEA'],
      control: 'required',
      actions: 'r',
      conditions: [
        '{zone-1/sys/user::owner}',
        {
          attributes: {
            'owner': '{user.id}'
          }
        }
      ]
    })

    assert.ok(acl.shouldApply(obj, 'r').ok)

    acl.authorize(obj, 'r', ['EMEA'], {user: {id: 123}}, function(err, result) {

      assert.ok(!err, err)

      assert.ok(result)
      assert.ok(result.authorize)

      assert.ok(result.inherit)
      assert.equal(result.inherit[0].id, 123)
      assert.ok(result.inherit[0].entity)
      assert.equal(result.inherit[0].entity.zone, 'zone-1')
      assert.equal(result.inherit[0].entity.base, 'sys')
      assert.equal(result.inherit[0].entity.name, 'user')

      obj.owner = 1234
      acl.authorize(obj, 'r', ['EMEA'], {user: {id: 123}}, function(err, result) {

        assert.ok(!err, err)

        assert.ok(result)
        assert.ok(!result.authorize)

        done()

      })

    })


  })


})
