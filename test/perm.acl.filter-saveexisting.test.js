/* Copyright (c) 2013-2014 Richard Rodger */
"use strict";


// mocha perm.test.js


var seneca  = require('seneca')

var assert  = require('chai').assert



describe('perm acl', function() {

  var si = seneca()

  si.use( require('../perm.js'), {
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
          attributes:{
            happy:1
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
        actions: ['save_new', 'save_existing','list', 'load', 'remove'],
        conditions: [],
      }
    ],
    allowedProperties: [{
      entity: {
        zone: undefined,
        base: undefined,
        name: 'foobar'
      },
      fields: ['id','name', 'number','happy','tacos']
    }]
  })

  it('seneca ready', function(done) {
    this.timeout(10000)
    si.ready(done)
  })

  // worked before this test.
  it('[save_new] filters should apply to conditional property.', function(done){
    var psiNoHappy = si.delegate({perm$:{roles:['foobar']}})

    var e = psiNoHappy.make('foobar',{a:'a',happy:1})
    
    e.save$(function(err,e){
      assert.isNull(err, err)
      assert.isNotNull(e, 'missing entity')
      assert.equal(e.happy, undefined,'should not have saved change to happy property') 

      done();
    })
  })
  
  it('[save_existing] filters should apply to conditional property.', function(done) {

    var psi = si.delegate({perm$:{roles:['foobar', 'happy']}})
    var psiNoHappy = si.delegate({perm$:{roles:['foobar']}})

    var pf1 = psi.make('foobar',{a:'a',happy:1})
    var pf1NoHappy = psiNoHappy.make('foobar',{b:'b',happy:1})

    ;pf1.save$(function(err, pf1){
      assert.isNull(err, err)
      console.log('saved ',pf1);

      assert.isNotNull(pf1.id, 'missing pf1.id')
      assert.equal(pf1.happy, 1)

    ;pf1NoHappy.load$(pf1.id,function(err, pf1NoHappy) {
      assert.isNull(err, err)
      assert.isNotNull(pf1NoHappy, 'missing entity')
      assert.equal(pf1NoHappy.happy, 1,'should not have saved change to happy property') 

      console.log('loaded happy entity',pf1NoHappy);

      pf1NoHappy.tacos = "yum"
      pf1NoHappy.happy = 0
      console.log("====================================++>>>>>>")
      console.log('attempting to make happy entity unhappy',pf1NoHappy);
    ;pf1NoHappy.save$(function(err, pf1NoHappy) {

      if(!pf1NoHappy.happy) console.log('happy entity shouldnt be unhappy!',pf1NoHappy);
      else console.log('yay still happy!');

      assert.isNull(err, err)
      assert.isNotNull(pf1NoHappy, 'missing entity')
      assert.equal(pf1NoHappy.happy, 1,'should not have saved change to happy property') 
      assert.equal(pf1NoHappy.tacos, "yum",'should have saved new tacos property')


      done()

    }) }) })

  })

})
