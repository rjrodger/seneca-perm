
var AccessControlProcedure = require('../lib/AccessControlProcedure.js')

var assert = require('assert')



describe('access controls', function() {
  describe('procedure 1', function() {

    var accessControlList1 = [{
      name: 'EMEA_region',
      roles: ['EMEA'],
      control: 'required',
      actions: 'r',
      conditions: [{
          attributes: {
            'region': 'EMEA'
          }
        }
      ]
    }, {
      name: 'legal_group',
      roles: ['legal'],
      control: 'required',
      actions: 'r',
      conditions: [{
          attributes: {
            'group': 'legal'
          }
        }
      ]
    }, {
      name: 'admin all access',
      roles: ['admin'],
      control: 'sufficient',
      actions: 'rw'
    }]

    var procedure1 = new AccessControlProcedure(accessControlList1)

    var emeaLegal = {
      region: 'EMEA',
      group: 'legal'
    }
    var emeaHR = {
      region: 'EMEA',
      group: 'HR'
    }
    var apacHR = {
      region: 'APAC',
      group: 'HR'
    }

    it('match', function(done) {

      procedure1.authorize(emeaLegal, 'r', ['EMEA', 'legal'], {}, function(err, result) {
        if(err) {
          return done(err)
        }

        assert.ok(result)
        assert.ok(result.authorize)
        assert.equal(result.history.length, accessControlList1.length)
        done()
      })

    })

    it('rejected by the second required', function(done) {

      procedure1.authorize(emeaLegal, 'r', ['EMEA'], {}, function(err, result) {
        if(err) {
          return done(err)
        }

        assert.ok(result)
        assert.ok(!result.authorize)
        assert.equal(result.history.length, accessControlList1.length)
        assert.equal(result.history[0].authorize, true)
        assert.equal(result.history[1].authorize, false)
        done()
      })

    })

    it('rejected by the first required', function(done) {

      procedure1.authorize(emeaLegal, 'r', ['legal'], {}, function(err, result) {
        if(err) {
          return done(err)
        }

        assert.ok(result)
        assert.ok(!result.authorize)
        assert.equal(result.history.length, accessControlList1.length)
        assert.equal(result.history[0].authorize, false)
        assert.equal(result.history[1].authorize, true)
        done()
      })

    })

    it('no conditions "sufficient" in ACL gives all access', function(done) {

      procedure1.authorize(emeaLegal, 'r', ['admin'], {}, function(err, result) {
        if(err) {
          return done(err)
        }

        assert.ok(result)
        assert.ok(result.authorize)
        assert.equal(result.history.length, accessControlList1.length)
        assert.equal(result.history[0].authorize, false)
        assert.equal(result.history[1].authorize, false)
        assert.equal(result.history[2].authorize, true)
        done()
      })

    })
  })


  describe('procedure 2', function() {

    var accessControlList2 = [{
      name: 'EMEA_region',
      roles: ['EMEA'],
      control: 'required',
      actions: 'r',
      conditions: [{
          attributes: {
            'region': 'EMEA'
          }
        }
      ]
    }, {
      name: 'admin all access',
      roles: ['admin'],
      control: 'sufficient',
      actions: 'rw'
    }, {
      name: 'does_not_exist all access',
      roles: ['requisite'],
      control: 'requisite',
      actions: 'rw'
    }, {
      name: 'never_used_all_access',
      roles: ['all_access'],
      control: 'sufficient',
      actions: 'rw'
    }]

    var procedure2 = new AccessControlProcedure(accessControlList2)

    var emea = {
      region: 'EMEA'
    }

    it('match', function(done) {

      procedure2.authorize(emea, 'r', ['EMEA', 'requisite'], {}, function(err, result) {
        if(err) {
          return done(err)
        }

        assert.ok(result)
        assert.ok(result.authorize)
        assert.equal(result.history.length, accessControlList2.length)
        done()
      })

    })


    it('no conditions "sufficient" in ACL gives all access', function(done) {

      procedure2.authorize(emea, 'r', ['admin'], {}, function(err, result) {
        if(err) {
          return done(err)
        }

        assert.ok(result)
        assert.ok(result.authorize)
        assert.equal(result.history.length, 2)
        assert.equal(result.history[0].authorize, false)
        assert.equal(result.history[1].authorize, true)
        done()
      })

    })

    it('"requisite" is absolutely mandatory', function(done) {

      procedure2.authorize(emea, 'r', ['EMEA', 'all_access'], {}, function(err, result) {
        if(err) {
          return done(err)
        }

        assert.ok(result)
        assert.ok(!result.authorize)
        assert.equal(result.history.length, 3)
        assert.equal(result.history[0].authorize, true)
        assert.equal(result.history[1].authorize, false)
        assert.equal(result.history[2].authorize, false)
        done()
      })

    })
  })

})
